# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

from abc import abstractmethod
from ava.core.context import get_core_context as _get_core_context


_actor_engine = None

def get_actor_engine():
    global _actor_engine
    if _actor_engine is None:
        _actor_engine = _get_core_context().lookup('actor_engine')
    return _actor_engine


class IActorRef(object):
    """ Represents a reference to an actor.
    """

    @abstractmethod
    def tell(self, message, *args, **kwargs):
        """ Sends the actor a message which should be a dict.
        :param message: the message to send.
        """

    @abstractmethod
    def ask(self, message, *args, **kwargs):
        """
        Sends the actor a request message.
        :param message: the request message to send.
        :return: a future result.
        """

    @abstractmethod
    def get_proxy(self):
        """ Gets the service proxy for the actor.
        """


class IActorProxy(object):
    """
    The marker interface for an actor proxy.
    """


class IActorContext(object):
    """ The interface to the actor framework service.
    """

    @abstractmethod
    def get_name(self):
        """
        :return: the name of the associated actor.
        """

    @abstractmethod
    def get_self_ref(self):
        """ Gets the reference to the actor associated with this context.

        :return: the actor's reference.
        """

    @abstractmethod
    def get_sender_ref(self):
        """ Gets the reference of the actor whose message is currently being
        processed.

        :return: the sender's reference.
        """

    @abstractmethod
    def spawn(self, actor_cls, *args, **kwargs):
        """
        Spawns a new actor.

        :param actor_cls: actor class
        :param args:
        :param kwargs:
        :return: a reference to the new actor instance.
        """

    @abstractmethod
    def make_ref(self, actor_name, address):
        """
        Makes an ActorRef from its components.

        :param actor_name: the actor's name to which the reference points.
        :param address: the transport address for the actor.
        :return:
        """


class Actor(object):
    """ Serves as the base class for actor implementations. It's not mandatory
    to inherit from this class to be compatible.
    """
    def __init__(self, context):
        self._context = context

    def on_message(self, msg):
        """
        Invoked if no other specific service method found.
        :param msg:
        :return:
        """
        pass


class ActorState(object):
    INITIAL = 0
    RUNNING = 1
    STOPPED = 2


__all__ = ['IActorRef', 'IActorContext', 'IActorProxy',
           'Actor', 'ActorState', 'get_actor_engine']
