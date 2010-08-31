# Copyright (c) 2010  Marien Zwart


"""HTTP protocol proxies."""


# TODO: This is a quick hack, clean it up later.


from __future__ import absolute_import, with_statement, division

import struct
from socket import inet_aton

from twisted.internet import defer, protocol, error
from twisted.protocols import basic


class ProxyChecker(object):

    def __init__(self, port):
        self.port = port

    def check(self, scan, env):
        creator = protocol.ClientCreator(
            env.reactor, self.protocol,
            env, '%s (%d)' % (self.message, self.port))
        # Disable the timeout here because our calling scanner should
        # cancel us just fine without it:
        d = creator.connectTCP(scan.ip, self.port, timeout=None)
        def connected(proto):
            return proto.deferred
        def connectFailed(fail):
            # If we could not connect for some sane reason it's just
            # not a proxy. Let unknown errors propagate though.
            fail.trap(error.ConnectionRefusedError, error.TCPTimedOutError)
        d.addCallbacks(connected, connectFailed)
        return d


class LineProtocol(basic.LineOnlyReceiver):

    delimiter = '\n'
    out_delimiter = '\r\n'

    def __init__(self, env, message):
        self.message = message
        self.target_ip = env.target_ip
        self.target_port = env.target_port
        self.target_url = env.target_url
        self.target_strings = env.target_strings
        self.max_bytes = env.max_bytes
        self.bytesReceived = 0

    def sendLine(self, line):
        """Override LineOnlyReceiver.sendLine to use a different delimiter."""
        return self.transport.writeSequence((line, self.out_delimiter))

    def sendLines(self, lines):
        out = []
        for line in lines:
            out.extend([line, self.out_delimiter])
        return self.transport.writeSequence(out)

    def connectionMade(self):
        self.deferred = defer.Deferred(self.cancel)

    def cancel(self, d):
        assert d is self.deferred
        self.deferred = None
        self.transport.loseConnection()

    def dataReceived(self, data):
        basic.LineOnlyReceiver.dataReceived(self, data)
        # HACK: check if our scan is in the line currently in
        # progress, if any. This should makes us catch things a little
        # faster if it takes them a while to get to the EOL, and is
        # critical if they never actually send an EOL.
        if self._buffer:
            self.check(self._buffer)
            # ... but don't count this against our bytesReceived
            # count, because we will check it again later. Note that
            # LineOnlyReceiver already rejects overly long lines, so
            # we don't have to worry about those overflowing us.
            self.bytesReceived -= len(self._buffer)

    def lineReceived(self, line):
        self.check(line)

    def check(self, data):
        self.bytesReceived += len(self._buffer)
        for target_string in self.target_strings:
            if target_string in data:
                d = self.deferred
                self.deferred = None
                d.callback(self.message)
                self.transport.loseConnection()
                return

        if self.bytesReceived > self.max_bytes:
            self.transport.loseConnection()
            self.connectionLost(None)

    def connectionLost(self, reason):
        if self.deferred is not None:
            # Paranoia.
            d = self.deferred
            self.deferred = None
            d.callback(None)


class HTTPConnectProtocol(LineProtocol):
    def connectionMade(self):
        LineProtocol.connectionMade(self)
        self.sendLines(['CONNECT %s:%d HTTP/1.0' % (self.target_ip,
                                                    self.target_port),
                        ''])

class HTTPConnectChecker(ProxyChecker):
    protocol = HTTPConnectProtocol
    message = 'HTTP CONNECT'


class HTTPPostProtocol(LineProtocol):
    def connectionMade(self):
        LineProtocol.connectionMade(self)
        self.sendLines(['POST %s HTTP/1.0' % (self.target_url,),
                        'Content-type: text/plain',
                        'Content-length: 5',
                        '',
                        'quit',
                        ''])

class HTTPPostChecker(ProxyChecker):
    protocol = HTTPPostProtocol
    message = 'HTTP POST'


class HTTPGetProtocol(LineProtocol):
    def connectionMade(self):
        LineProtocol.connectionMade(self)
        self.sendLines(['GET %s HTTP/1.0' % (self.target_url,), ''])

class HTTPGetChecker(ProxyChecker):
    protocol = HTTPGetProtocol
    message = 'HTTP GET'


class WingateProtocol(LineProtocol):
    def connectionMade(self):
        LineProtocol.connectionMade(self)
        self.sendLine('%s:%d' % (self.target_ip, self.target_port))

class WingateChecker(ProxyChecker):
    protocol = WingateProtocol
    message = 'Wingate'


class CiscoProtocol(LineProtocol):
    def connectionMade(self):
        LineProtocol.connectionMade(self)
        self.sendLines(['cisco',
                        'telnet %s %d' % (self.target_ip, self.target_port)])

class CiscoChecker(ProxyChecker):
    protocol = CiscoProtocol
    message = 'cisco router (telnet)'


# SOCKS4 isn't really a "line based" protocol, but we can treat its
# incoming traffic as lines and bypass LineProtocol when sending.

# http://ftp.cerias.purdue.edu/pub/tools/dos/socks.cstc/socks4/SOCKS4.protocol
# was used as reference.

class SOCKS4Protocol(LineProtocol):
    def connectionMade(self):
        LineProtocol.connectionMade(self)
        self.transport.write(struct.pack(
                '!BBH4sB',
                4, # version
                1, # command (1 for CONNECT)
                self.target_port,
                inet_aton(self.target_ip),
                0)) # terminator for our user-id (empty string).

class SOCKS4Checker(ProxyChecker):
    protocol = SOCKS4Protocol
    message = 'SOCKS 4'

# http://tools.ietf.org/html/rfc1928 was used as reference.
class SOCKS5Protocol(LineProtocol):
    def connectionMade(self):
        LineProtocol.connectionMade(self)
        self.transport.write(struct.pack(
                '!BBB',
                5, # version
                1, # number of supported methods
                0, # anonymous
                ))
        # HACK: just send the CONNECT request straight away instead of
        # waiting for the server to reply to our negotiation.
        self.transport.write(struct.pack(
                '!BBBB4sH',
                5, # version
                1, # command (1 for CONNECT)
                0, # reserved
                1, # address type (1 for IPv4 address)
                inet_aton(self.target_ip),
                self.target_port))

class SOCKS5Checker(ProxyChecker):
    protocol = SOCKS5Protocol
    message = 'SOCKS 5'
