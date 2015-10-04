# -*- coding: utf-8 -*-
""" Service interface for network transport mechanism.
"""
from __future__ import absolute_import, print_function, unicode_literals


class Candidate(object):
    """ Candidate transport address
    """
    KIND_HOST = 0
    KIND_RELAYED = 1
    KIND_SERVER_REFLEXIVE = 2
    KIND_PEER_REFLEXIVE = 3

    def __init__(self, kind, address, priority=0):
        self._kind = kind
        self._address = address
        self._priority = priority
        self._foundation = None

    @property
    def kind(self):
        return self._kind

    @property
    def address(self):
        return self._address

    @property
    def priority(self):
        return self._priority

    @property
    def foundation(self):
        return self._foundation

    def __repr__(self):
        return "Candidate[kind=%d, address=%r, priority=%d]" % (
            self._kind, self._address, self._priority,
        )
