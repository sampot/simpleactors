# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

class ActorError(RuntimeError):
    def __init__(self, *args, **kwargs):
        super(ActorError, self).__init__(*args, **kwargs)


class ActorAlreadyStarted(ActorError):
    """ Raised to indicate the actor has already started.
    """
    pass


class ActorAlreadyStopped(ActorError):
    """ Raised to indicate the actor has already stopped.
    """
    pass

class RequestTimeout(ActorError):
    """ Raised to indicates a request has time out.
    """
    pass


class StopActor(ActorError):
    """ Raised to cause a actor to stop processing.
    """
    pass

__all__ = ['ActorError', 'StopActor']
