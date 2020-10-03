from twisted.internet  import defer, error, protocol, interfaces
from twisted.protocols import basic

class HeaderProtocol(basic.LineOnlyReceiver):
    delimeter = b"\n"

    def __init__(self, bad):
        self._lines = set([])
        self.bad = bad

    def connectionMade(self):
        self.deferred = defer.Deferred(self.cancel)
        self.transport.write(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
    def cancel(self, defer):
        if defer is self.deferred:
            self.deferred = None
            self.transport.loseConnection()
    def connectionLost(self, reason):
        if self.deferred is not None:
            self.deferred.callback(None)

    def lineReceived(self, line):
        line = line.decode("utf8").strip("\r")
        if not line:
            # two consecutive newlines
            self.transport.loseConnection()
        else:
            self._lines.add(line)

            for key, bad_headers in self.bad.items():
                if (self._lines&bad_headers) == bad_headers:
                    d = self.deferred
                    self.deferred = None
                    d.callback(f"HTTP headers ({key})")
                    self.transport.loseConnection()

class HeaderChecker(object):
    def __init__(self, port, bad):
        self.port = port

        # convert {k: [v1,v2]} in to {k: set([v1,v2])}
        self.bad  = {k: set(v) for k, v in bad.items()}

    def check(self, scan, env):
        creator = protocol.ClientCreator(env.reactor, HeaderProtocol,
                                         self.bad)
        if env.bind_address:
            bindAddress = (env.bind_address, 0)
        else:
            bindAddress = None
        # Disable the timeout here because our calling scanner should
        # cancel us just fine without it:
        d = creator.connectTCP(scan.ip, self.port, timeout=None,
                                   bindAddress=bindAddress)

        def connected(proto):
            return proto.deferred
        def connectFailed(fail):
            # If we could not connect for some sane reason it's just
            # not a proxy. Let unknown errors propagate though.
            fail.trap(error.ConnectionRefusedError, error.TCPTimedOutError)
        d.addCallbacks(connected, connectFailed)

        return d
