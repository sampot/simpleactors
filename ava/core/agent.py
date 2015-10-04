# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, unicode_literals

# hack for setting default encoding!
import sys
reload(sys)  # Reload does the trick!
sys.setdefaultencoding('UTF8')

import gevent
# from gevent import monkey
# monkey.patch_all()
# monkey.patch_all(thread=False)

from gevent.event import Event

import os
import sys
import logging
import importlib

import inspect
__ssl__ = __import__('ssl')

try:
    _ssl = __ssl__._ssl
except AttributeError:
    _ssl = __ssl__._ssl2

from collections import OrderedDict

from . import context
from .defines import INSTALLED_ENGINES
from .signals import AGENT_STARTED, AGENT_STOPPING
from .errors import AgentStopped

logger = logging.getLogger(__name__)

__agent = None

agent_running = Event()
agent_stopped = Event()


def new_sslwrap(sock, server_side=False, keyfile=None, certfile=None, cert_reqs=__ssl__.CERT_NONE, ssl_version=__ssl__.PROTOCOL_SSLv23, ca_certs=None, ciphers=None):
    context = __ssl__.SSLContext(ssl_version)
    context.verify_mode = cert_reqs or __ssl__.CERT_NONE
    if ca_certs:
        context.load_verify_locations(ca_certs)
    if certfile:
        context.load_cert_chain(certfile, keyfile)
    if ciphers:
        context.set_ciphers(ciphers)

    caller_self = inspect.currentframe().f_back.f_locals['self']
    return context._wrap_socket(sock, server_side=server_side, ssl_sock=caller_self)


def _mygetfilesystemencoding():
    old = sys.getfilesystemencoding

    def inner_func():
        ret = old()
        if ret is None:
            return 'utf-8'
        else:
            return ret
    return inner_func


def patch_sys_getfilesystemencoding():
    # sys.getfilesystemencoding() always returns None when frozen on Ubuntu systems.
    patched_func = _mygetfilesystemencoding()
    sys.getfilesystemencoding = patched_func


def restart_later():
    if __agent.running:
        logger.warning("Agent not stopped successfully!")
    sys.exit(1)


def signal_handler(signum = None, frame = None):
    logger.debug("Received HUP signal, requests the shell to restart.")
    global __agent
    if __agent:
        __agent._stop_engines()
    sys.exit(1)


def load_class(full_class_string):
    """
    dynamically load a class from a string. e.g. 'a.b.package:classname'
    """

    class_data = full_class_string.split(":")
    module_path = class_data[0]
    class_name = class_data[1]

    module = importlib.import_module(module_path)
    # Finally, we retrieve the Class
    return class_name, getattr(module, class_name)


class Agent(object):
    def __init__(self):
        logger.debug("Initializing agent...")
        global agent_running
        agent_running.clear()

        patch_sys_getfilesystemencoding()

        # in case ssl.sslwrap is gone for 2.7.9, patch it.
        if not hasattr(_ssl, 'sslwrap'):
            _ssl.sslwrap = new_sslwrap

        self.running = False
        self.interrupted = False
        self._greenlets = []
        self._context = context.get_core_context(self)
        self._engines = OrderedDict()

        # if hasattr(signal, 'SIGHUP'):
        #    signal.signal(signal.SIGHUP, signal_handler)

    def stop(self):
        self.interrupted = True

    def add_child_greenlet(self, child):
        self._greenlets.append(child)

    def _start_engines(self):
        for it in INSTALLED_ENGINES:
            logger.debug("Loading engine: %s", it)
            try:
                name, engine_cls = load_class(it)
                engine = engine_cls()
                self._engines[name] = engine
            except:
                logger.error("Failed to create engine.", exc_info=True)

        logger.debug("Starting engines...")
        for name, engine in self._engines.iteritems():
            try:
                # logger.debug("Starting engine: %s", name)
                engine.start(self._context)
            except:
                logger.error("Failed to start engine: %s" % name,
                             exc_info=True)

        self._context.send(signal=AGENT_STARTED, sender=self)

    def _stop_engines(self):
        self._context.send(signal=AGENT_STOPPING, sender=self)

        engines = self._engines.values()
        engines.reverse()
        for engine in engines:
            try:
                engine.stop(self._context)
            except:
                logger.warning("Error while stopping %r", engine)

    def context(self):
        return self._context

    def run(self):
        logger.debug("Starting agent...")
        global agent_running, agent_stopped
        self._start_engines()

        self.running = True
        agent_running.set()
        logger.debug("Agent started.")

        while not self.interrupted:
            try:
                gevent.joinall(self._greenlets, timeout=1)
            except KeyboardInterrupt:
                logger.debug("Interrupted.")
                break

        # stop engines in reverse order.
        self._stop_engines()

        gevent.killall(self._greenlets, timeout=1)

        self.running = False
        agent_stopped.set()
        logger.debug("Agent stopped.")


def start_agent():
    global __agent
    __agent = Agent()
    __agent.run()


if __name__ == '__main__':
    start_agent()
