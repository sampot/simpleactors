# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

import logging
import socket

from . import defines as D
from .endpoint import DummyEndpoint

_logger = logging.getLogger(__name__)


class TransportEngine(object):
    """ Responsible for starting up network transport service.
    """
    def __init__(self):
        self._context = None
        self._endpoint = None
        self._init_endpoint()
        self._endpoint.find_local_address()
        _logger.debug("Transport engine created.")

    def _init_endpoint(self):
        listen_port = D.DEFAULT_PORT
        listen_ip = D.DEFAULT_IP

        if listen_ip is None:
            _logger.debug("No transport port configured, use default one.")
            listen_ip = D.DEFAULT_PORT
        if listen_ip is None:
            listen_ip = ''

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind((listen_ip, listen_port))
            self._endpoint = DummyEndpoint(sock=sock)
            return
        except IOError:
            pass

        # bind to random port
        sock.bind((listen_ip, 0))
        self._endpoint = DummyEndpoint(sock=sock)

    def start(self, context):
        self._context = context
        self._endpoint.start()
        _logger.debug("Endpoint bound to: %r", self._endpoint.local_address())
        context.bind(D.ENDPOINT_CONTEXT_KEY, self._endpoint)
        _logger.debug("Transport engine started.")

    def stop(self, context):
        context.unbind(D.ENDPOINT_CONTEXT_KEY)
        if self._endpoint:
            self._endpoint.stop()
        _logger.debug("Transport engine stopped.")
