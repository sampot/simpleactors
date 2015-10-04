# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

from ..core import AvaError

class TransportError(AvaError):
    pass


class ConnectionNotAvailable(TransportError):
    """ Raised to indicate the connection ID is not available.
    """
    pass

class MalformedPacket(TransportError):
    pass




