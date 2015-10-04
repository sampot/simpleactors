# -*- coding: utf-8 -*-
from __future__ import print_function, division, absolute_import

import os
import logging
import socket
import random
import gevent

from .connection import DummyConnection
from .packet import PacketParser

END_MARKER = os.urandom(32)

_logger = logging.getLogger(__name__)


class Endpoint(object):
    MTU = 8192

    logger = logging.getLogger(__name__)

    """
    Encapsulate UDP socket as the transport for peer communication.
    """
    def __init__(self, address=('', 0), sock=None):
        self._bind_address = address
        self._stopped = False
        self._local_address = None
        self._external_address = None
        self._nat_type = None
        self._mtu = Endpoint.MTU
        if sock:
            self._socket = sock
        else:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.bind(self._bind_address)
        self._available = False
        self._conn_by_addr = {}
        self._msg_listener = None

        self._receiver = None

    @property
    def mtu(self):
        """ Gets the maximum transport unit in bytes.
        :return:
        """
        return self._mtu

    @property
    def available(self):
        return self._available

    def has_public_address(self):
        """
        :return: True if the node is using a public address.
        """
        return self._local_address == self._external_address

    def local_address(self):
        """
        Gets the local address.
        :return: address tuple (host, port)
        """
        return self._local_address

    def set_message_listener(self, listener):
        self._msg_listener = listener

    def _set_connection(self, remote_addr, local_conn_id, conn):
        self._conn_by_addr[remote_addr] = conn

    def _remove_connection(self, remote_addr, local_conn_id):
        if remote_addr in self._conn_by_addr:
            del self._conn_by_addr[remote_addr]

    def start(self):
        self._receiver = gevent.spawn(self._receive_loop)
        self._receiver.start()

    def stop(self):
        """
        Gracefully stop the transport.
        """
        self._stopped = True
        # send self a dummy packet
        self.send_message(END_MARKER, self._local_address)

    def wait_until_available(self, timeout=5):
        secs = int(timeout)

        for s in range(secs):
            if self.available:
                break
            gevent.sleep(1)

        return self.available

    def find_local_address(self):
        if self._local_address:
            return self._local_address

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip, _ = s.getsockname()
            _, port = self._socket.getsockname()
            self._local_address = (ip, port)
            s.close()
            _logger.debug("Found local address:%r", self._local_address)
            return self._local_address
        except IOError as ex:
            self.logger.error(ex)

    def send_message(self, msg, addr, *args, **kwargs):
        """
        Invoked by upper layer to send a message to the specified address.

        :param msg: the message to sent. Must be a byte string.
        :param addr: the destination adress.
        """
        conn = self._conn_by_addr.get(addr)
        if not conn:
            conn = DummyConnection(self, addr)
            self._conn_by_addr[addr] = conn

        conn.message_sent(msg, addr, *args, **kwargs)

    def _deliver_message(self, message, address, *args, **kwargs):
        """
        Invoked by connections to deliver messages to upper layer.

        :param message: the byte string of data
        :param address: remote transport address
        :return:
        """
        if self._msg_listener:
            try:
                # print('%r from %r' % (bytes(message), address))
                self._msg_listener.message_received(message, address,
                                                    *args, **kwargs)
            except:
                _logger.error("Error in delivering message to upper layer.",
                              exc_info=True)

    def _send_packet(self, packet, addr):
        """
        Invoked by a connection to actually send the packet to the
        specified address.

        :param packet: the packet data.
        :param addr: address tuple (host, port)
        :return:
        """
        self._socket.sendto(packet, addr)

    def _handle_packet(self, packet, address):
        """
        Invoked by the receiver to deliver packets to corresponding channels.

        :param packet: the packet object.
        :param address: the remote transport address.
        """
        # if connection exists, ask the connection to handle the packet.
        conn = self._conn_by_addr.get(address)
        if conn is None:
            conn = DummyConnection(self, address)
            self._conn_by_addr[address] = conn

        conn.packet_received(packet, address)

    def _receive_loop(self):
        self.logger.debug("Receiver is running...")
        self.find_local_address()

        try:
            self._available = True
            while not self._stopped:
                data, addr = self._socket.recvfrom(Endpoint.MTU)
                if END_MARKER in data:
                    _logger.info("END MARKER received, stop.")
                    self._stopped = True
                    break
                # _logger.debug("Received a packet: %r", data)
                try:
                        packet = PacketParser.parse(data)
                        self._handle_packet(packet, addr)
                except RuntimeError:
                    _logger.error("Error in processing incoming packet.",
                                  exc_info=True)
        finally:
            self._available = False
            self._receiver = None


class DummyEndpoint(Endpoint):
    def __init__(self, address=('', 0), sock=None, find_external=False):
        super(DummyEndpoint, self).__init__(address,
                                            sock)
