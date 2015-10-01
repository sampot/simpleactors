# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

import os
import random
import logging
import inspect
import time
import msgpack
import gevent
import base58
import uuid
import socket

from gevent.local import local
from collections import OrderedDict

from gevent.event import AsyncResult
from gevent.queue import Queue, Empty

from . import defines as D
from .message import MessageType, Message, Request, Error, Result, BaseMessage
from .errors import ActorError, RequestTimeout
from .service import *


_logger = logging.getLogger(__name__)

# Greenlet-local storage for getting sender's name
__current_actor = local()

def get_current_context():
    """ Gets the actor's current context.

    :return:
    """
    global __current_actor
    return getattr(__current_actor, 'context', None)


def set_current_context(ctx):
    global __current_actor
    __current_actor.context = ctx


class ActorRef(IActorRef):
    """ Represents a reference to an actor.
    """
    def __init__(self, engine, actor_name, address):
        self.engine = engine
        self.actor_name = actor_name
        self.address = address
        self.proxy = None

    def __eq__(self, other):
        return (self.address == other.address
                and self.actor_name == other.actor_name)

    def tell(self, message, *args, **kwargs):
        """ Sends the actor a message. No response is expected.
        """

        ctx = get_current_context()
        message.sender = ctx.get_name()
        message.receiver = self.actor_name
        self.engine.request_async(message, self.address)

    def ask(self, message, *args, **kwargs):
        ctx = get_current_context()
        message.sender = ctx.get_name()
        message.receiver = self.actor_name
        result = self.engine.call_async(message, self.address)
        return result

    def get_proxy(self):
        if self.proxy is None:
            self.proxy = ActorProxy(self)
        return self.proxy

    def serialize(self):
        ip = socket.inet_aton(self.address[0])
        return msgpack.packb((ip, self.address[1], self.actor_name))

    def __str__(self):
        return "%s:%d:%s" % (self.address[0], self.address[1], self.actor_name)

    def __repr__(self):
        return "ActorRef[%s:%d:%s]" % (self.address[0],
                                       self.address[1],
                                       self.actor_name)


class Action(object):
    """ Encapsulates the information for invoking an action.
    """
    def __init__(self, action_name, actor_ref, timeout=None, oneway=False):
        """

        :param action_name: action name.
        :param actor_ref: the reference of the actor which performs the action.
        :param timeout: the default timeout in seconds.
        :return:
        """
        self.action_name = action_name
        self.actor_ref = actor_ref
        self.timeout = timeout
        self.oneway = oneway

    def __call__(self, *args, **kwargs):
        msg = Request(q=self.action_name,
                      a=kwargs)
        if self.oneway:
            self.actor_ref.tell(msg)
        else:
            result = self.actor_ref.ask(msg)
            return result.get(timeout=self.timeout)


class ActorProxy(IActorProxy):
    """ The service proxy for caller side.
    """
    def __init__(self, actor_ref, timeout=None):
        self.actor_ref = actor_ref
        self.timeout = timeout
        self.actions = {}

    def __getattribute__(self, action_name):
        actions = object.__getattribute__(self, 'actions')
        action = actions.get(action_name)
        if action is None:
            ref = object.__getattribute__(self, 'actor_ref')
            timeout = object.__getattribute__(self, 'timeout')
            oneway = action_name.endswith('_oneway')
            key = action_name
            if oneway:
                action_name = action_name[:-7]
            action = Action(action_name, ref, timeout, oneway)
            actions[key] = action
        return action


class ActorContext(IActorContext):
    """ The implementation of IActorContext.
    """
    def __init__(self, actor_ref):
        self._actor = None
        self._actor_ref = actor_ref
        self._engine = actor_ref.engine
        self._inbox = Queue()
        self._runner = None
        self._state = ActorState.INITIAL
        # current sender's name
        self._sender_name = None
        self._sender_ref = None
        self._sender_addr = None

    def get_name(self):
        return self._actor_ref.actor_name

    def get_self_ref(self):
        """ Gets the reference to the actor associated with this context.

        :return: the actor's reference.
        """
        return self._actor_ref

    def get_sender_ref(self):
        if not self._sender_ref:
            self._sender_ref = ActorRef(self._engine,
                                        self._sender_name,
                                        self._sender_addr)
        return self._sender_ref

    def spawn(self, actor_cls, *args, **kwargs):
        return self._engine.spawn(actor_cls, *args, **kwargs)

    def make_ref(self, actor_name, address):
        """
        Makes an ActorRef from its components.

        :param actor_name: the actor's name to which the reference points.
        :param address: the transport address for the actor.
        :return:
        """
        return ActorRef(self._engine, actor_name, address)

    def serialize_ref(self, actor_ref):
        """ Converts the specified actor reference to a serialized form.

        :param actor_ref:
        :return:
        """
        return actor_ref.serialize()

    def deserialize_ref(self, ref_str):
        """ Converts a serialized actor reference to its object form.

        :param ref_str:
        :return:
        """
        parts = msgpack.unpackb(ref_str)
        if len(parts) != 3:
            raise ValueError("Malformed actor reference: %r", ref_str)
        ip_addr = socket.inet_ntoa(parts[0])
        address = (ip_addr, parts[1])
        return ActorRef(self._engine, parts[2], address)

    def set_current(self):
        """ Sets the context be the current one
        """
        set_current_context(self)

    def start(self):
        self._actor = self._engine.get_actor(self._actor_ref.actor_name)
        self._runner = gevent.Greenlet(self._run)
        self._runner.start()

    def stop(self):
        self._state = ActorState.STOPPED
        self._runner.join(1)
        self._runner = None
        self._actor = None
        self._actor_ref = None

    def _handle_message(self, msg, address):
        """ Invoked by engine to handle a message destined to this actor.
        """
        # _logger.debug("Actor '%s' is handling message: %r", self.get_name(), msg)
        self._sender_name = msg.sender
        self._sender_ref = None
        self._sender_addr = address

        if isinstance(msg, Request):
            action = msg.action
            handler = getattr(self._actor, 'on_' + action, None)
            if not handler or not callable(handler):
                # fall back to generic action handler.
                handler = getattr(self._actor, 'handle_action', None)

            if handler and callable(handler):
                try:
                    # _logger.debug("arguments: %r", msg.arguments)
                    result = handler(*[], **msg.arguments)
                    res = msg.success_response()
                    res.value = result
                    self._engine.request_async(res, address)

                except Exception as ex:
                    _logger.exception("Error in handling action:%s", action)
                    err = msg.error_response()
                    err.code = 401
                    err.reason = ex.message
                    self._engine.request_async(err, address)
            else:
                err = msg.error_response()
                err.code = 402
                err.reason = 'Action not allowed.'

        elif isinstance(msg, Message):
            handler = getattr(self._actor, 'handle_message', None)
            if handler and callable(handler):
                try:
                    handler(msg)
                except Exception as ex:
                    _logger.exception("Error in handling generic message.")

    def _handle_timer(self):
        handler = getattr(self._actor, 'handle_timer', None)
        if handler and callable(handler):
            try:
                handler()
            except Exception as ex:
                _logger.exception("Error in handler timer event.")

    def _post_message(self, msg_address):
        # _logger.debug("Actor '%s' got a message from %r",
        #               self._actor_ref.actor_name, msg_address[1])
        self._inbox.put(msg_address)

    def _run(self):
        self._state = ActorState.RUNNING
        set_current_context(self)

        _logger.debug("Actor '%s' is running...", self.get_name())

        try:
            while self._state == ActorState.RUNNING:
                try:
                    msg, address = self._inbox.get(timeout=30)
                    self._handle_message(msg, address)
                except Empty:
                    self._handle_timer()
        finally:
            _logger.debug("Actor: %r stopped.", self.get_name())
            set_current_context(None)
            self._engine.remove_actor(self.get_name())


class FutureResult(object):
    """
    Future results for asynchronous operations.
    """
    def __init__(self):
        self._result = AsyncResult()
        self.created_at = time.time()

    def get(self, timeout=None):
        return self._result.get(block=True, timeout=timeout)

    def set(self, value):
        self._result.set(value)

    def set_exception(self, exception):
        self._result.set_exception(exception)


class ActorEngine(object):
    """
    """
    def __init__(self, endpoint=None):
        self._endpoint = endpoint
        if self._endpoint is not None:
            self._endpoint.set_message_listener(self)

        self._actors = {}
        self._actor_contexts = {}
        self._transactions = OrderedDict()
        self._cleaner = None
        self._cleanup_interval = 30
        self._expired_timeout = 30 * 60  # 30 minutes

        _logger.debug("Actor Engine created.")

    def start(self, ctx=None):
        if ctx and self._endpoint is None:
            self._endpoint = ctx.lookup("endpoint")
            if self._endpoint is None:
                raise RuntimeError("No transport endpoint available!")

            _logger.debug("Transport endpoint from context is used.")
            self._endpoint.set_message_listener(self)

        self._cleaner = gevent.Greenlet(run=self._cleanup)
        self._cleaner.start()

        if ctx is not None:
            ctx.bind(D.ENGINE_CONTEXT_KEY, self)

        _logger.debug("Actor Engine started.")

    def stop(self, ctx=None):
        if self._cleaner:
            self._cleaner.kill()
            self._cleaner = None

        _logger.debug("Actor Engine stopped.")

    def call_async(self, request, address):
        """ Asynchronously make a RPC request, a future result is expected.

        :param request:
        :param address:
        :return:
        """
        _logger.debug("call_async")
        tid = self._next_message_id()
        future = FutureResult()
        self._transactions[tid] = future

        request.msg_id = tid
        if address == self._endpoint.local_address():
            self._dispatch_message(request, address)
        else:
            msg_data = msgpack.packb(request)
            self._endpoint.send_message(msg_data, address)
        return future

    def request_async(self, request, address):
        """ Makes a RPC request which no result is expected.
        :param request:
        :param address:
        :return:
        """
        if address == self._endpoint.local_address():
            self._dispatch_message(request, address)
        else:
            msg_data = msgpack.packb(request)
            self._endpoint.send_message(msg_data, address)

    def spawn(self, actor_cls, *args, **kwargs):
        return self.spawn_named(self._random_actor_name(),
                                actor_cls,
                                *args, **kwargs)

    def spawn_named(self, name, actor_cls, *args, **kwargs):
        argspec = inspect.getargspec(actor_cls.__init__)
        _actor_ref = ActorRef(self,
                              name,
                              address=self._endpoint.local_address())
        context = ActorContext(_actor_ref)
        self._actor_contexts[_actor_ref.actor_name] = context

        # _logger.debug("argspec: %r", argspec)
        if 'actor_context' in argspec.args:
            _logger.debug("actor requires a context object.")
            kwargs['actor_context'] = context
        _actor = actor_cls(*args, **kwargs)
        self._actors[_actor_ref.actor_name] = _actor

        context.start()
        return _actor_ref

    def get_actor(self, actor_name):
        """ Gets the actor instance by specified name.

        :param actor_name:
        :return:
        """
        return self._actors.get(actor_name)

    def remove_actor(self, actor_name):
        """  Called by actor runner to remove the specified actor.

        :param actor_name:
        :return:
        """
        if actor_name in self._actors:
            del self._actors[actor_name]

        if actor_name in self._actor_contexts:
            del self._actor_contexts[actor_name]

    def message_received(self, msg_data, address, *args, **kwargs):
        """ The transport notifies that a message has arrived.
        :param msg_data:
        :param address:
        :return:
        """
        assert isinstance(msg_data, bytes) or isinstance(msg_data, buffer)
        msg = msgpack.unpackb(msg_data, use_list=False)

        # _logger.debug("Actor Engine: received a message: %r", msg)
        msg_type = msg.get(b'y')
        msg_obj = None
        if msg_type == MessageType.REQUEST:
            msg_obj = Request(**msg)
        elif msg_type == MessageType.RESULT:
            msg_obj = Result(**msg)
        elif msg_type == MessageType.ERROR:
            msg_obj = Error(**msg)
        else:
            msg_obj = Message(**msg)

        self._dispatch_message(msg_obj, address)

    def _dispatch_message(self, msg, address):
        assert isinstance(msg, BaseMessage)
        if isinstance(msg, Request):
            self._handle_request(msg, address)
        elif isinstance(msg, Result):
            self._handle_result(msg, address)
        elif isinstance(msg, Error):
            self._handle_error(msg, address)
        else:
            self._handle_message(msg, address)

    def _handle_message(self, msg, address):
        # _logger.debug("Actor Engine: _handle_message: %r", msg)
        actor_ctx = self._actor_contexts.get(msg.receiver)
        if actor_ctx:
            actor_ctx._post_message((msg, address))
        else:
            _logger.debug("No actor bound to the name: %r", msg.receiver)

    def _handle_request(self, request, address):
        # _logger.debug("Actor Engine: _handle_request: %r", request)
        actor_ctx = self._actor_contexts.get(request.receiver)
        if actor_ctx:
            actor_ctx._post_message((request, address))
        else:
            _logger.debug("No actor bound to the name: %r", request.receiver)

    def _handle_result(self, result, address):
        # _logger.debug("Actor Engine: _handle_result: %r", result)
        tid = result.msg_id
        future = self._transactions.get(tid)
        if future:
            del self._transactions[tid]
            future.set(result.value)

    def _handle_error(self, error, address):
        # _logger.debug("Actor Engine: _handle_error: %r", error)
        tid = error.msg_id
        future = self._transactions.get(tid)
        if future:
            del self._transactions[tid]
            msg = 'RPC Error: code=%d, reason=%s' % (error.code, error.reason)
            future.set_exception(ActorError(msg))

    def _cleanup(self):
        """ Regularly clean up outdated transactions.
        """
        while True:
            # run every 30 seconds
            gevent.sleep(self._cleanup_interval)
            # _logger.debug("Cleaning up expired transactions...")
            # _logger.debug("Expire timeout: %d", self._expired_timeout)
            num_visited = 0
            num_purged = 0
            now = time.time()
            expired = now - self._expired_timeout

            for tid, tx in self._transactions.iteritems():
                num_visited += 1
                if tx.created_at < expired:
                    # tx.set_exception(ex)
                    del self._transactions[tid]
                    num_purged += 1
                else:
                    break
                if num_visited > 1000:
                    break

            if num_purged:
                _logger.debug("%d transactions purged.", num_purged)

    def _next_message_id(self):
        while True:
            tid = random.randint(0, 2147483648)  # 2**31
            if tid not in self._transactions:
                return tid

    def _random_actor_name(self):
        #oid = uuid.uuid1().get_bytes()

        while True:
            oid = os.urandom(4)
            oid = base58.b58encode(oid)
            if oid not in self._actors:
                return oid
