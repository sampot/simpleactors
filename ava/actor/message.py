# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

from abc import ABCMeta

class InvalidMessage(RuntimeError):
    pass

class MessageType(object):
    GENERAL = b'm'
    REQUEST = b'q'
    ERROR = b'e'
    RESULT = b'r'


class BaseMessage(dict):
    """ Represents higher-level structure for messaging.
    """
    __metaclass__ = ABCMeta

    def __init__(self, *args, **kwargs):
        super(BaseMessage, self).__init__(args, **kwargs)
        self.update(*args, **kwargs)
        sender = kwargs.pop('sender', None)
        if sender:
            self[b's'] = sender

        receiver = kwargs.pop('receiver', None)
        if receiver:
            self[b'p'] = receiver

    def __getitem__(self, key):
        val = dict.__getitem__(self, key)
        return val

    def __setitem__(self, key, val):
        dict.__setitem__(self, key, val)

    def __repr__(self):
        dictrepr = dict.__repr__(self)
        return '%s(%s)' % (type(self).__name__, dictrepr)

    def update(self, *args, **kwargs):
        for k, v in dict(*args, **kwargs).iteritems():
            self[k] = v

    @property
    def msg_type(self):
        """
        :return: the message's type
        """
        return self.get(b'y')

    @property
    def msg_id(self):
        """
        :return: the message's identifier.
        """
        return self.get(b't')

    @msg_id.setter
    def msg_id(self, mid):
        self[b't'] = mid

    @property
    def receiver(self):
        """
        :return: the receiver's ID or name.
        """
        return self.get(b'p')

    @receiver.setter
    def receiver(self, receiver):
        self[b'p'] = receiver

    @property
    def sender(self):
        """

        :return: the sender's ID or name.
        """
        return self.get(b's')

    @sender.setter
    def sender(self, s):
        self[b's'] = s

    def _set_type(self, msg_type):
        self[b'y'] = msg_type

class Message(BaseMessage):
    """ General message.
    """
    def __init__(self, *args, **kwargs):
        super(Message, self).__init__(*args, **kwargs)
        self._set_type(MessageType.GENERAL)


class Request(BaseMessage):
    def __init__(self, *args, **kwargs):
        super(Request, self).__init__(*args, **kwargs)
        self._set_type(MessageType.REQUEST)

    @property
    def action(self):
        return self.get(b'q')

    @action.setter
    def action(self, act):
        self[b'q'] = act

    @property
    def arguments(self):
        return self.get(b'a')

    @arguments.setter
    def arguments(self, args):
        self[b'a'] = args

    def success_response(self):
        """ Makes a Result message for responding to this request.
        :return: the message with essential attributes preset.
        """
        res = Result()
        res.receiver = self.sender
        res.sender = self.receiver
        res.msg_id = self.msg_id
        return res

    def error_response(self):
        """ Makes a Error message for responding to this request.
        :return: the message with essential attributes preset.
        """
        err = Error()
        err.receiver = self.sender
        err.sender = self.receiver
        err.msg_id = self.msg_id
        return err


class Error(BaseMessage):
    def __init__(self, *args, **kwargs):
        super(Error, self).__init__(*args, **kwargs)
        self._set_type(MessageType.ERROR)
        if not self.code:
            self[b'code'] = 201

        if not self.reason:
            self[b'reason'] = b'generic error'

    @property
    def code(self):
        return self.get(b'code')

    @code.setter
    def code(self, c):
        self[b'code'] = c

    @property
    def reason(self):
        return self.get(b'reason')

    @reason.setter
    def reason(self, r):
        self[b'reason'] = r

class Result(BaseMessage):
    def __init__(self, *args, **kwargs):
        super(Result, self).__init__(*args, **kwargs)
        self._set_type(MessageType.RESULT)

    @property
    def value(self):
        return self.get(b'r')

    @value.setter
    def value(self, val):
        self[b'r'] = val


__all__ = ['Message', 'Request', 'Result', 'Error', 'BaseMessage']
