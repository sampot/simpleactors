# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

import struct

from . import errors

VERSION = 1

FLAG_HAS_OPTIONS = 0x01
FLAG_HAS_CONTENT = 0x02
FLAG_BLOCK_BEGIN = 0x04
FLAG_BLOCK_END = 0x08

MAX_PACKET_SIZE = 1024
MAX_BUFFER_SIZE = 4096

# bit-fields sample
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |0 0 0 0 0 0 0 0|0 0 0 0 0 0 0 0|0 0 0 0 0 0 0 0|0 0 0 0 0 0 0 0|
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

class Option(object):
    """ Represent an option in options part of a frame.
    An option is represented in type-length-value format.
    type: 1 octet: option type
    length: 1 octet: the sum of type, length and value fields.
    value: variable length
    """
    FMT = b'!BB%ds'

    def __init__(self, kind=0xff, value=b''):
        self._kind = kind
        self._value = value

    @property
    def kind(self):
        return self._kind

    @property
    def length(self):
        if self._kind == 0xff:
            return 1
        return len(self._value) + 2

    @property
    def value(self):
        return self._value

    def pack_into(self, buf, offset=0):
        if self._kind != 0xff:
            fmt = Option.FMT % len(self._value)
            struct.pack_into(fmt, buf, offset,
                             self._kind, len(self._value), self._value)
            offset += struct.calcsize(fmt)
        else:
            struct.pack_into(b'!B', buf, offset, 0xff)
            offset += 1

        return offset

    def unpack_from(self, buf, offset=0):
        if isinstance(buf, bytearray):
            buf = buffer(buf)
        self._kind = ord(buf[offset])
        if self._kind != 0xff:
            opt_len = ord(buf[offset+1])
            offset += 2
            fmt = b'%ds' % opt_len
            t = struct.unpack_from(fmt, buf[offset:offset+opt_len])
            self._value = t[0]
            return offset + opt_len
        else:
            self._value = b''
            return offset + 1

    def pack(self):
        buf = bytearray(self.length)
        offset = self.pack_into(buf)
        return buffer(buf, 0, offset)


class EndMarkerOption(Option):
    """ The option to mark the end of options part, begin of content part.
    """
    def __init__(self):
        super(EndMarkerOption, self).__init__(0xff, b'')

class TokenOption(Option):
    """ Opaque value
    """
    def __init__(self, token=None):
        super(TokenOption, self).__init__(0x01, value=token)

    @property
    def token(self):
        return self._value

class IPAddrOption(Option):
    """ TheIP Address
    """
    def __init__(self, ip=None):
        super(IPAddrOption, self).__init__(0x02, value=ip)

    @property
    def ip_addr(self):
        return self.value

class PortOption(Option):
    """ The port number in a IP address.
    """
    def __init__(self, port=0):
        super(PortOption, self).__init__(0x03, value=struct.pack('!H', port))

    def port(self):
        return struct.unpack('!H', self.value)

class SeqNoOption(Option):
    """ Sequence number
    """
    def __init__(self, seq_no=0):
        value = struct.pack('!H', seq_no)
        super(SeqNoOption, self).__init__(value=value)

    @property
    def seq_no(self):
        return struct.unpack('!H', self._value)


class OptionFactory(object):
    _options_classes = {
        0x01: TokenOption,
        0xff: EndMarkerOption,
    }

    @staticmethod
    def create(opt_kind):
        cls = OptionFactory._options_classes.get(opt_kind)
        if not cls:
            raise errors.MalformedPacket('Unknown option: %r' % opt_kind)
        return cls()


class Frame(object):
    FMT = b'!BBH'
    HEADER_SIZE = 4

    """
    The data unit in a packet.
    |kind|flags|length|options|content|
    - kind: 1 byte
    - flags: 1 byte:
      - bit 0: the frame has options part
      - bit 1: the frame has content part
    - length: unsigned short (16 bits): the length of the frame.
    - options: variable length
    """
    def __init__(self, kind=0, flags=0, options=None):
        """

        :param kind: the frame type
        :param flags: type-specific flags.
        :param options: optional parameters for the frame.
        """
        self._kind = kind
        self._flags = flags
        self._options = options
        self._length = 0

    @property
    def kind(self):
        return self._kind

    @property
    def flags(self):
        return self._flags

    @property
    def options(self):
        return self._options

    def pack_into(self, buf, offset=0):
        """ Packs the frame to a buffer.
        :return: size of the packed data
        """
        old_offset = offset
        if self._options:
            self._flags |= FLAG_HAS_OPTIONS

        offset += Frame.HEADER_SIZE
        if self._options:
            for opt in self._options:
                offset = opt.pack_into(buf, offset)

            # end marker
            buf[offset] = 0xff
            offset += 1

        self._length += (offset - old_offset)
        struct.pack_into(Frame.FMT, buf, old_offset,
                         self._kind, self._flags, self._length)
        return offset

    def unpack_from(self, buf, offset=0):
        """ Unpacks the frame from the specified buffer.

        :param buf:
        """
        if isinstance(buf, bytearray):
            buf = buffer(buf)
        prefix_size = Packet.HEADER_LEN
        prefix = struct.unpack_from(Frame.FMT, buf[offset:offset+prefix_size])
        self._kind = prefix[0]
        self._flags = prefix[1]
        self._length = prefix[2]
        offset += Frame.HEADER_SIZE
        if self._flags & FLAG_HAS_OPTIONS:
            self._options = []
            while True:
                opt_type = ord(buf[offset])
                if opt_type == 0xff:
                    offset += 1
                    break
                option = OptionFactory.create(opt_type)
                offset = option.unpack_from(buf, offset)
                self._options.append(option)

        return offset

    def pack(self):
        buf = bytearray(MAX_BUFFER_SIZE)
        offset = self.pack_into(buf)
        return buffer(buf, 0, offset)


class DataFrame(Frame):
    """ Contains data for upper layer
    """
    KIND_ID = 1

    def __init__(self, flags=0x0c, options=None, content=None):
        # By default, the data frame is the first and final fragment of the
        # data block. That is, it's the only data frame.
        super(DataFrame, self).__init__(DataFrame.KIND_ID, flags, options)
        if content is not None:
            assert isinstance(content, bytes)
        self._content = content

    @property
    def content(self):
        return self._content

    def set_first_fragment(self, flag):
        if flag:
            self._flags |= FLAG_BLOCK_BEGIN
        else:
            self._flags &= (~FLAG_BLOCK_BEGIN)

    def is_first_fragment(self):
        return (self._flags & FLAG_BLOCK_BEGIN) != 0

    def set_last_fragment(self, flag):
        if flag:
            self._flags |= FLAG_BLOCK_END
        else:
            self._flags &= (~FLAG_BLOCK_END)

    def is_last_fragment(self):
        return (self._flags & FLAG_BLOCK_END) != 0

    def unpack_from(self, buf, offset=0):
        old_offset = offset
        offset = super(DataFrame, self).unpack_from(buf, offset)
        content_len = self._length - (offset - old_offset)
        if self._flags & FLAG_HAS_CONTENT:
            self._content = buffer(buf, offset, content_len)
            offset += content_len
        else:
            self._content = b''

        return offset

    def pack_into(self, buf, offset=0):
        if self._content:
            self._flags |= FLAG_HAS_CONTENT
            self._length += len(self._content)
        offset = super(DataFrame, self).pack_into(buf, offset)
        if self._content:
            fmt = b'!%ds' % len(self._content)
            struct.pack_into(fmt, buf, offset, self._content)
            offset += struct.calcsize(fmt)

        return offset


class AckFrame(Frame):
    """ Acknowledge the receive of a message.
    """
    def __init__(self):
        super(AckFrame, self).__init__(2)


class FrameFactory(object):

    _frame_classes = {
        1: DataFrame,
        2: AckFrame,
    }

    @staticmethod
    def create(frame_kind):
        cls = FrameFactory._frame_classes.get(frame_kind)
        if not cls:
            raise errors.MalformedPacket("Unknown frame type: %d" % frame_kind)

        return cls()


class Packet(object):
    """ Represents packets for wire transmission. A packet has a header, and
    may contain 0, 1, or more frames.
    """
    HEADER_LEN = 6
    HEADER_FMT = b'!BBHH'

    def __init__(self, pkt_kind, version=1, flags=0,
                 source_conn_id=0, target_conn_id=0,
                 options=None):
        self._version = version
        self._kind = pkt_kind
        self._flags = flags
        self._source_conn_id = source_conn_id
        self._target_conn_id = target_conn_id
        self._options = options

    @property
    def kind(self):
        return self._kind

    @property
    def version(self):
        return self._version

    @property
    def source_conn_id(self):
        return self._source_conn_id

    @property
    def target_conn_id(self):
        return self._target_conn_id

    def unpack_from(self, buf, offset=0):
        t = struct.unpack_from(Packet.HEADER_FMT,
                               buf[offset:offset + Packet.HEADER_LEN])
        if len(t) != 4:
            raise errors.MalformedPacket(Packet.HEADER_FMT)

        offset += Packet.HEADER_LEN
        self._kind = t[0] & 0x3f
        self._version = (t[0] >> 6) & 0x03
        if self._version != 1:
            raise errors.MalformedPacket()
        self._flags = t[1]
        self._source_conn_id = t[2]
        self._target_conn_id = t[3]

        if self._flags & FLAG_HAS_OPTIONS:
            self._options = []
            while offset < len(buf):
                opt_type = ord(buf[offset])
                if opt_type == 0xff:
                    offset += 1
                    break
                option = OptionFactory.create(opt_type)
                offset = option.unpack_from(buf, offset)
                self._options.append(option)
        return offset

    def pack_into(self, buf, offset=0):
        if self._options:
            self._flags |= FLAG_HAS_OPTIONS
        struct.pack_into(Packet.HEADER_FMT, buf, offset,
                         (self._version << 6) | self._kind,
                         self._flags,
                         self._source_conn_id,
                         self._target_conn_id)
        offset += struct.calcsize(Packet.HEADER_FMT)
        if self._options:
            for opt in self._options:
                offset = opt.pack_into(buf, offset)

        return offset

    def pack(self):
        buf = bytearray(MAX_BUFFER_SIZE)
        offset = self.pack_into(buf)
        return buffer(buf, 0, offset)


class FramePacket(Packet):
    """ Data packet for carrying frames.
    """
    def __init__(self, version=1, flags=0, frames=None):
        super(FramePacket, self).__init__(pkt_kind=1,
                                          version=version,
                                          flags=flags)

        if frames:
            self._frames = list(frames)
        else:
            self._frames = []

    @property
    def frames(self):
        return tuple(self._frames)

    def append(self, frame):
        self._frames.append(frame)

    def unpack_from(self, buf, offset=0):
        if isinstance(buf, bytearray):
            buf = buffer(buf)

        offset = super(FramePacket, self).unpack_from(buf, offset)
        size = len(buf)
        if self._flags & FLAG_HAS_CONTENT:
            self._frames = []
            while offset < size:
                frame_type = ord(buf[offset])
                frame = FrameFactory.create(frame_type)
                offset = frame.unpack_from(buf, offset)
                self._frames.append(frame)

    def pack_into(self, buf, offset=0):
        self._flags |= FLAG_HAS_CONTENT
        offset = super(FramePacket, self).pack_into(buf, offset)
        for frame in self._frames:
            offset = frame.pack_into(buf, offset)

        return offset


class StunRequestPacket(Packet):
    """ For acquiring peer reflexive address.
    """
    def __init__(self):
        super(StunRequestPacket, self).__init__(pkt_kind=2)


class StunResponsePacket(Packet):
    def __init__(self):
        super(StunResponsePacket, self).__init__(pkt_kind=3)
        self.external_ip = None
        self.external_port = None


class HelloPacket(Packet):
    """ Sent by initiator to start a connection.
    """
    def __init__(self, conn_pk=None, source_conn_id=None):
        super(HelloPacket, self).__init__(pkt_kind=4)
        self._conn_pk = conn_pk
        self._source_conn_id = source_conn_id


class WelcomePacket(Packet):
    """ Sent by responder to the initiator to establish a connection.
    """
    def __init__(self, cookie=None):
        super(WelcomePacket, self).__init__(pkt_kind=5)
        self._cookie = cookie


class AuthRequestPacket(Packet):
    """ Sent by the initiator to request a mutual authentication.
    """
    def __init__(self, public_key=None, encrypted_cookie=None):
        super(AuthRequestPacket, self).__init__(pkt_kind=6)
        self._public_key = public_key
        self._cookie = encrypted_cookie


class AuthResponsePacket(Packet):
    """ The response of a mutual authentication.
    """
    def __init__(self, peer_pk=None):
        super(AuthResponsePacket, self).__init__(pkt_kind=7)
        self._peer_pk = peer_pk


class ResetPacket(Packet):
    """ Sent to indicate a connection doesn't exist or is closed.
    """
    def __init__(self):
        super(ResetPacket, self).__init__(pkt_kind=8)


class PacketParser(object):
    """ Responsible for creating packet instances by data.
    """
    _packet_classes = {
        1: FramePacket,
        2: StunRequestPacket,
        3: StunResponsePacket,
        4: HelloPacket,
        5: WelcomePacket,
        6: AuthRequestPacket,
        7: AuthResponsePacket,
        8: ResetPacket,
    }

    @staticmethod
    def create(pkt_kind):
        cls = PacketParser._packet_classes.get(pkt_kind)
        if not cls:
            raise errors.MalformedPacket("Unknown packet kind: %r" % pkt_kind)

        return cls()

    @staticmethod
    def parse(pkt_data):
        buf = pkt_data if isinstance(pkt_data, buffer) else buffer(pkt_data)
        kind = ord(buf[0]) & 0x3f
        pkt = PacketParser.create(kind)
        pkt.unpack_from(pkt_data)
        return pkt
