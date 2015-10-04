# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

import logging
from abc import abstractmethod
from gevent.queue import Queue, Empty

from .packet import *
from .errors import MalformedPacket

_logger = logging.getLogger(__name__)


class Connection(object):
    """ A virtual connection for communication.
    """

    @abstractmethod
    def message_sent(self, message, address, *args, **kwargs):
        """
        Invoked to send the message to another endpoint.
        :param message:
        :param address:
        """

    @abstractmethod
    def packet_received(self, packet, address, *args, **kwargs):
        """ Handles the received packet, deliver to upper layer if it has
        a message.
        :param packet:
        :param address:
        """

    def close(self):
        """ Releases the resources associated with the connection.
        """
        pass


class MockConnection(Connection):
    """
    For testing.
    """
    def __init__(self):
        super(MockConnection, self).__init__()
        self.outbox = []
        self.inbox = []

    def message_sent(self, message, address, *args, **kwargs):
        frame = DataFrame(content=message)
        packet = FramePacket(frames=[frame])

        self.outbox.append((packet.pack(), address))

    def packet_received(self, packet, address, *args, **kwargs):
        if not isinstance(packet, FramePacket):
            return

        for frame in packet.frames:
            if isinstance(frame, DataFrame):
                msg = frame.content
                self.inbox.append((msg, address))


class DummyConnection(Connection):

    def __init__(self, endpoint, remote_address, local_conn_id=0):
        self._endpoint = endpoint
        self._remote_address = remote_address
        self._local_conn_id = local_conn_id
        self._messages_sent = 0
        self._packets_received = 0

    def packet_received(self, packet, address, *args, **kwargs):
        self._packets_received += 1

        if not isinstance(packet, FramePacket):
            return

        for frame in packet.frames:
            if isinstance(frame, DataFrame):
                msg = frame.content
                self._endpoint._deliver_message(msg, address)

    def message_sent(self, message, address, *args, **kwargs):
        self._messages_sent += 1

        # no message fragmentation support yet.
        frame = DataFrame(content=message)
        packet = FramePacket(frames=[frame])
        self._endpoint._send_packet(packet.pack(), address)


class EndpointConnection(Connection):
    """ The connection implementation used with Endpoint object.
    """
    _ST_INITIAL = 0         # initial state
    _ST_CONNECTING = 1      # connecting to the peer
    _ST_CONNECTED = 2       # connected.
    _ST_AVAILABLE = 3       # peer's is authenticated.
    _ST_CLOSING = 4         # disconnecting from the peer
    _ST_CLOSED = 5          # disconnected from the peer.

    def __init__(self, endpoint, remote_address):
        super(EndpointConnection, self).__init__()

        self._state = self._ST_INITIAL
        self._endpoint = endpoint
        self._local_address = endpoint.local_address()
        self._local_conn_id = 0
        self._local_conn_sk = None  # local short-term secret key
        self._remote_address = remote_address
        self._remote_conn_id = 0
        self._remote_conn_pk = None  # remote peer's short-term public key
        self._outbox = Queue()
        self._transmitter = None

    def message_sent(self, message, address, *args, **kwargs):
        """ Invoked to send a message via the connection to another endpoint.

        :param message: the message to send.
        :param address: the destination transport address.
        :return:
        """
        self._outbox.put((message, address))

    def packet_received(self, packet, address, *args, **kwargs):
        """
        Invoked to handle a received packet for this connection.

        :param packet: the packet.
        :param address: the source transport address.
        :return:
        """
        try:
            if isinstance(packet, FramePacket):
                self._handle_frame(packet)
            elif isinstance(packet, HelloPacket):
                self._handle_hello(packet)
            elif isinstance(packet, WelcomePacket):
                self._handle_welcome(packet)
            elif isinstance(packet, AuthRequestPacket):
                self._handle_auth_request(packet)
            elif isinstance(packet, AuthResponsePacket):
                self._handle_auth_response(packet)
            elif isinstance(packet, ResetPacket):
                self._handle_reset(packet)
            else:
                _logger.debug("Unknown packet: %r", packet)
        except MalformedPacket:
            _logger.error('Error in handling packet.', exc_info=True)

        # if a message packet, deliver it to upper layer.
        # self._endpoint._deliver_message(message, address)

    def close(self):
        self._endpoint.close_connection(self._remote_address,
                                        self._local_conn_id)

    def _handle_frame(self, pkt):
        if self._state != self._ST_AVAILABLE:
            return

    def _handle_hello(self, pkt):
        if self._state != self._ST_INITIAL:
            return

    def _handle_welcome(self, pkt):
        if self._state != self._ST_CONNECTING:
            return

    def _handle_auth_request(self, pkt):
        pass

    def _handle_auth_response(self, pkt):
        pass

    def _handle_reset(self, pkt):
        self._state = self._ST_CLOSED
        self.close()
