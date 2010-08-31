# Copyright (c) 2010  Marien Zwart


"""Tests for the proxy checkers."""


from __future__ import absolute_import, with_statement, division

from twisted.trial import unittest
from twisted.internet import task, defer, error
from twisted.test import proto_helpers

from .. import proxy, scanner


class TestError(ValueError):
    """Caught by some tests."""


class TestProtocol(proxy.LineProtocol):
    def connectionMade(self):
        proxy.LineProtocol.connectionMade(self)
        self.sendLine('this is a line')


class TestChecker(proxy.ProxyChecker):
    protocol = TestProtocol
    message = 'TEST'


def _createEnv(reactor):
    env = scanner.ScanEnvironment(reactor, None)
    env.target_ip = '1.2.3.4'
    env.target_port = 8
    env.target_url = 'http://localhost/cookie'
    env.target_strings = ['killme']
    env.max_bytes = 1024
    return env


class ProxyCheckerTest(unittest.TestCase):

    def setUp(self):
        self.reactor = proto_helpers.MemoryReactor()
        self.env = _createEnv(self.reactor)
        self.clock = task.Clock()
        self.checker = TestChecker(5)
        self.scan = scanner.Scan(self.clock, '127.0.0.1')

    def testCheckConnects(self):
        self.checker.check(self.scan, self.env)
        self.assertEqual(1, len(self.reactor.tcpClients))
        host, port, factory, timeout, bindAddress = self.reactor.tcpClients[0]
        self.assertEqual('127.0.0.1', host)
        self.assertEqual(5, port)
        self.assertIdentical(None, timeout)
        self.assertIdentical(None, bindAddress)

    def testConnectFailed(self):
        d = self.checker.check(self.scan, self.env)
        host, port, factory, timeout, bindAddress = self.reactor.tcpClients[0]

        # HACK: this makes some assumptions about how ClientCreator works.
        factory.reactor = self.clock
        factory.clientConnectionFailed(None, TestError())
        self.clock.advance(0)

        return self.assertFailure(d, TestError)

    def testConnectCancelled(self):
        d = self.checker.check(self.scan, self.env)
        host, port, factory, timeout, bindAddress = self.reactor.tcpClients[0]

        d.cancel()

        # XXX this should test the connector actually had disconnect called,
        # but MemoryReactor does not conveniently allow it

        return self.assertFailure(d, defer.CancelledError)

    def testConnectSucceeded(self):
        d = self.checker.check(self.scan, self.env)
        host, port, factory, timeout, bindAddress = self.reactor.tcpClients[0]

        # HACK: this makes some assumptions about how ClientCreator works.
        factory.reactor = self.clock

        transport = proto_helpers.StringTransport()

        proto = factory.buildProtocol(None)
        proto.transport = transport
        proto.connectionMade()

        self.assertEqual('this is a line\r\n', transport.value())

        self.clock.advance(0)

        proto.connectionLost(error.ConnectionDone())

        return d

    def testConnectionCancelled(self):
        d = self.checker.check(self.scan, self.env)
        host, port, factory, timeout, bindAddress = self.reactor.tcpClients[0]

        # HACK: this makes some assumptions about how ClientCreator works.
        factory.reactor = self.clock

        transport = proto_helpers.StringTransport()

        proto = factory.buildProtocol(None)
        proto.transport = transport
        proto.connectionMade()

        self.clock.advance(0)

        d.cancel()
        self.failUnless(transport.disconnecting)
        return self.assertFailure(d, defer.CancelledError)


class LineProtocolTest(unittest.TestCase):

    def setUp(self):
        self.env = _createEnv(None)
        self.proto = proxy.LineProtocol(self.env, 'Test Message')
        self.transport = proto_helpers.StringTransport()
        self.proto.transport = self.transport
        self.proto.connectionMade()
        # Careful: self.proto.deferred gets set to None, so save it here:
        self.deferred = self.proto.deferred

    @defer.inlineCallbacks
    def testInnocent(self):
        self.proto.dataReceived('I am not a proxy!\r\n')
        self.proto.connectionLost(None)
        result = yield self.deferred
        self.assertIdentical(None, result)

    @defer.inlineCallbacks
    def testNotSoInnocent(self):
        self.proto.dataReceived('killme\r\n')
        self.failUnless(self.transport.disconnecting)
        result = yield self.deferred
        self.assertEqual('Test Message', result)

    @defer.inlineCallbacks
    def testIncompleteLine(self):
        self.proto.dataReceived('killme')
        self.failUnless(self.transport.disconnecting)
        result = yield self.deferred
        self.assertEqual('Test Message', result)

    def testSendLine(self):
        self.proto.sendLine('a line')
        self.assertEqual('a line\r\n', self.transport.value())

    def testSendLines(self):
        self.proto.sendLines(['1', '2'])
        self.assertEqual('1\r\n2\r\n', self.transport.value())

    @defer.inlineCallbacks
    def testLimit(self):
        self.proto.dataReceived(2048 * 'a')
        self.failUnless(self.transport.disconnecting)
        result = yield self.deferred
        self.assertIdentical(None, result)

    # TODO: some more strenuous tests of our modified newline handling
    # and data received limits might be nice. These would be a little
    # clunky though, since accepting just \n as a newline is really
    # just an optimization when combined with checking incomplete
    # lines.


class SimpleProtocolTest(unittest.TestCase):

    def setUp(self):
        self.env = _createEnv(None)

    def _testProto(self, cls, data):
        proto = cls(self.env, 'a message')
        proto.transport = proto_helpers.StringTransport()
        proto.connectionMade()
        self.assertEqual(data, proto.transport.value())

    def testHTTPConnect(self):
        self._testProto(proxy.HTTPConnectProtocol,
                        'CONNECT 1.2.3.4:8 HTTP/1.0\r\n\r\n')

    def testHTTPPost(self):
        self._testProto(proxy.HTTPPostProtocol,
                        'POST http://localhost/cookie HTTP/1.0\r\n'
                        'Content-type: text/plain\r\n'
                        'Content-length: 5\r\n'
                        '\r\n'
                        'quit\r\n'
                        '\r\n')

    def testHTTPGet(self):
        self._testProto(proxy.HTTPGetProtocol,
                        'GET http://localhost/cookie HTTP/1.0\r\n\r\n')

    def testWingate(self):
        self._testProto(proxy.WingateProtocol,
                        '1.2.3.4:8\r\n')

    def testCisco(self):
        self._testProto(proxy.CiscoProtocol,
                        'cisco\r\ntelnet 1.2.3.4 8\r\n')

    def testSOCKS4(self):
        self._testProto(proxy.SOCKS4Protocol,
                        '\x04\x01\x00\x08\x01\x02\x03\x04\x00')

    def testSOCKS5(self):
        self._testProto(proxy.SOCKS5Protocol,
                        '\x05\x01\x00'
                        '\x05\x01\x00\x01\x01\x02\x03\x04\x00\x08')

