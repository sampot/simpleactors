# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

import gevent
from gevent import monkey
monkey.patch_all(thread=False)
from gevent.event import AsyncResult

import msgpack
import logging
import pytest

from ava.actor.engine import ActorEngine, ActorRef
from ava.actor import engine
from ava.actor import message


logging.basicConfig(level=logging.DEBUG)


class MockEndpoint(object):
    def __init__(self):
        self._listener = None
        self.sent_messages = []

    def set_message_listener(self, listener):
        self._listener = listener

    def send_message(self, msg, address):
        self.sent_messages.append((msg, address))

    def post_message(self, msg, address):
        if self._listener:
            self._listener.message_received(msg, address)

    def pump_message(self):
        """ Pumps a sent message back to the listener.
        """
        if len(self.sent_messages) == 0:
            return

        msg, address = self.sent_messages.pop()

        if self._listener:
            self._listener.message_received(msg, address)

    def local_address(self):
        return '127.0.0.1', 80

class MockActorContext(object):
    def __init__(self, actor_name):
        self._actor_name = actor_name

    def get_name(self):
        return self._actor_name


@pytest.fixture
def endpoint():
    return MockEndpoint()

@pytest.fixture
def actor_engine(request, endpoint):
    engine = ActorEngine(endpoint)

    def clean():
        engine.stop(None)

    request.addfinalizer(clean)
    engine.start(None)
    return engine

@pytest.fixture
def actor_engine2(request, endpoint):
    engine = ActorEngine(endpoint)

    return engine


class TestActorRef(object):

    def test_create_ref(self, actor_engine):
        ac = MockActorContext('test_actor')
        engine.set_current_context(ac)
        ref = ActorRef(actor_engine, 'tester', ('127.0.0.1', 80))

        assert ref.engine is actor_engine
        assert ref.actor_name == 'tester'
        assert ref.address == ('127.0.0.1', 80)

    def test_can_tell_actor(self, actor_engine, endpoint):
        ac = MockActorContext('test_actor')
        engine.set_current_context(ac)

        ref = ActorRef(actor_engine, 'tester', ('10.0.0.1', 80))
        ref.tell(message.Message())

        assert len(endpoint.sent_messages) == 1

    def test_can_ask_actor(self, actor_engine, endpoint):
        ref = ActorRef(actor_engine, 'tester', ('10.0.0.1', 80))
        try:
            result = ref.ask(message.Message())
            result.get(1)
            pytest.xfail('timeout should happen.')
        except:
            pass

        assert len(endpoint.sent_messages) == 1

    def test_actor_proxy(self, actor_engine):
        ref = ActorRef(actor_engine, 'tester', ('127.0.0.1', 80))

        def ask(msg):
            assert msg is not None
            result = AsyncResult()
            result.set('world')
            return result

        ref.ask = ask
        proxy = ref.get_proxy()
        hello = proxy.hello
        assert callable(hello)
        assert 'world' == hello()



class TestActorContext(object):

    def test_can_set_and_get_context(self):
        engine.set_current_context(ctx={})

        assert engine.get_current_context() is not None

    def test_ref_serialization(self, actor_engine):
        ref = ActorRef(actor_engine, 'tester', ('127.0.0.1', 80))
        ctx = engine.ActorContext(ref)
        str1 = ctx.serialize_ref(ref)
        ref2 = ctx.deserialize_ref(str1)
        assert ref == ref2


class PongActor(object):
    instance = None

    def __init__(self, actor_context):
        self.context = actor_context
        print("PongActor created.")
        self.called = False
        self.last_msg = None
        PongActor.instance = self

    def on_ping(self, s):
        self.called = True
        self.last_msg = s
        return s

    def on_error(self):
        self.called = True
        raise RuntimeError('Pong error')

    def on_get_sender(self):
        self.called = True
        return self.context.get_sender_ref().actor_name

    def handle_message(self, msg):
        self.called = True
        self.last_msg = msg

    def handle_action(self, *args, **kwargs):
        self.called = True
        self.last_msg = kwargs
        return kwargs

class PingActor(object):
    instance = None

    def __init__(self, actor_context):
        self.context = actor_context
        PingActor.instance = self


class TestActor(object):

    def test_can_spawn_actor(self, actor_engine):

        ping_ref = actor_engine.spawn(PingActor)
        assert ping_ref is not None
        assert ping_ref.actor_name is not None

        ping = PingActor.instance
        engine.set_current_context(ping.context)

        pong_ref = actor_engine.spawn(PongActor)
        assert pong_ref is not None

    def test_can_tell_actor(self, actor_engine):
        ping_ref = actor_engine.spawn(PingActor)
        assert ping_ref is not None

        ping = PingActor.instance
        engine.set_current_context(ping.context)

        pong_ref = actor_engine.spawn(PongActor)
        pong = PongActor.instance
        req = message.Request()
        req.receiver = pong_ref.actor_name
        req.action = 'ping'
        req.arguments = {'s': 'hello'}

        pong_ref.tell(req)
        gevent.sleep(0.5)
        assert pong.called
        assert 'hello' == pong.last_msg

    def test_can_send_message_to_actor(self, actor_engine):
        ping_ref = actor_engine.spawn(PingActor)
        assert ping_ref is not None

        ping = PingActor.instance
        engine.set_current_context(ping.context)

        pong_ref = actor_engine.spawn(PongActor)
        pong = PongActor.instance
        msg = message.Message()
        msg.receiver = pong_ref.actor_name
        msg.msg_id = b'msgid1234'

        pong_ref.tell(msg)
        gevent.sleep(0.5)
        assert pong.called
        assert isinstance(pong.last_msg, message.Message)
        assert b'msgid1234' == pong.last_msg.msg_id

    def test_can_ask_actor(self, actor_engine):
        ping_ref = actor_engine.spawn(PingActor)
        assert ping_ref is not None

        ping = PingActor.instance
        engine.set_current_context(ping.context)

        pong_ref = actor_engine.spawn(PongActor)
        pong = PongActor.instance
        req = message.Request()
        req.receiver = pong_ref.actor_name
        req.action = 'ping'
        req.arguments = {'s': 'hello'}

        result = pong_ref.ask(req)
        text = result.get(1)

        assert pong.called
        assert 'hello' == text

    def test_ask_actor_with_generic_action(self, actor_engine):
        ping_ref = actor_engine.spawn(PingActor)
        assert ping_ref is not None

        ping = PingActor.instance
        engine.set_current_context(ping.context)

        pong_ref = actor_engine.spawn(PongActor)
        pong = PongActor.instance
        req = message.Request()
        req.receiver = pong_ref.actor_name
        req.action = 'not_exist'
        req.arguments = {'s': 'hello'}

        result = pong_ref.ask(req)
        text = result.get(1)

        assert pong.called
        assert text is not None
        assert 'hello' == text.get('s')

    def test_call_actor_via_proxy(self, actor_engine):
        ping_ref = actor_engine.spawn(PingActor)
        assert ping_ref is not None

        ping = PingActor.instance
        engine.set_current_context(ping.context)

        pong_ref = actor_engine.spawn(PongActor)

        pong = pong_ref.get_proxy()
        text = pong.ping(s='world')

        assert 'world' == text

    def test_oneway_call_actor_via_proxy(self, actor_engine):
        ping_ref = actor_engine.spawn(PingActor)
        assert ping_ref is not None

        engine.set_current_context(PingActor.instance.context)

        pong_ref = actor_engine.spawn(PongActor)

        pong = pong_ref.get_proxy()
        pong.ping.oneway = True
        # tell() should be used under the hood.
        result = pong.ping(s='1234')
        gevent.sleep(0.5)
        assert PongActor.instance.called
        assert result is None

    def test_call_actor_with_oneway_suffix(self, actor_engine):
        ping_ref = actor_engine.spawn(PingActor)
        assert ping_ref is not None

        engine.set_current_context(PingActor.instance.context)

        pong_ref = actor_engine.spawn(PongActor)

        pong = pong_ref.get_proxy()
        # tell() should be used under the hood.
        result = pong.ping_oneway(s='1234')
        gevent.sleep(0.5)
        assert PongActor.instance.called
        assert result is None

    def test_call_actor_via_proxy_with_error(self, actor_engine):
        ping_ref = actor_engine.spawn(PingActor)
        assert ping_ref is not None

        ping = PingActor.instance
        engine.set_current_context(ping.context)

        pong_ref = actor_engine.spawn(PongActor)

        pong = pong_ref.get_proxy()
        with pytest.raises(engine.ActorError):
            text = pong.error()


class TestActorEngine(object):

    def test_can_clean_expired_transactions(self, actor_engine2):
        ref = ActorRef(actor_engine2, 'tester', ('10.0.0.1', 80))
        actor_engine2._cleanup_interval = 0.5
        actor_engine2._expired_timeout = 2
        actor_engine2.start(None)

        req = message.Request()
        req.receiver = 'not_existent'
        req.action = 'hello'
        for i in range(5):
            ref.ask(req)
            gevent.sleep(0.5)
        gevent.sleep(2)
        actor_engine2.stop(None)

    def test_get_and_remove_actor(self, actor_engine2):
        ping_ref = actor_engine2.spawn(PingActor)
        ping_actor = actor_engine2.get_actor(ping_ref.actor_name)

        assert ping_actor is not None
        assert isinstance(ping_actor, PingActor)

        actor_engine2.remove_actor(ping_ref.actor_name)

        ping_actor = actor_engine2.get_actor(ping_ref.actor_name)
        assert ping_actor is None

    def test_get_and_remove_named_actor(self, actor_engine2):
        ping_ref = actor_engine2.spawn_named('ping', PingActor)
        assert ping_ref.actor_name == 'ping'

        ping_actor = actor_engine2.get_actor(ping_ref.actor_name)

        assert ping_actor is not None
        assert isinstance(ping_actor, PingActor)

        actor_engine2.remove_actor(ping_ref.actor_name)

        ping_actor = actor_engine2.get_actor(ping_ref.actor_name)
        assert ping_actor is None

    def test_can_deliver_message_to_actor(self, actor_engine):
        pong_ref = actor_engine.spawn(PongActor)
        pong = PongActor.instance

        msg = dict(y='m', p=pong_ref.actor_name, s=b'1234')
        msg = msgpack.packb(msg)
        actor_engine.message_received(msg, ('10.0.0.1', 80))
        gevent.sleep(0.5)
        assert pong.called

    def test_can_deliver_request_to_actor(self, actor_engine):
        pong_ref = actor_engine.spawn(PongActor)
        pong = PongActor.instance

        msg = dict(y='q', p=pong_ref.actor_name, s=b'1234', q='ping',
                   a={'s': 'world'})
        msg = msgpack.packb(msg)
        actor_engine.message_received(msg, ('10.0.0.1', 80))
        gevent.sleep(0.5)
        assert pong.called
