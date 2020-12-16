from twisted.internet  import defer, error, protocol, interfaces, ssl
from twisted.protocols import basic

class BannerProtocol(basic.LineOnlyReceiver):
    delimiter = b"\n"

    def __init__(self, bad, send):
        self.send   = send
        self.bad    = bad
        self._lines = set([])
        self._buf   = b""

    def connectionMade(self):
        self.deferred = defer.Deferred(self.cancel)
        if self.send:
            self.transport.write(self.send.encode("utf8"))
    def cancel(self, defer):
        if defer is self.deferred:
            self._check_leftover()
            self.deferred = None
            self.transport.loseConnection()
    def connectionLost(self, reason):
        if self.deferred is not None:
            if not self._check_leftover():
                self.deferred.callback(None)
            self.deferred = None

    def dataReceived(self, data):
        self._buf += data
        super().dataReceived(data)

    def lineReceived(self, line):
        # cut a single line off the start of _buf
        self._buf = self._buf.split(b"\n", 1)[1]
        line      = line.decode("utf8").strip("\r")

        if (not line or                 # two consecutive newlines
                len(self._lines) > 20): # too many lines
            self.transport.loseConnection()
        elif self.deferred is not None:
            self._lines.add(line)
            if self._check():
                self.deferred = None
                self.transport.loseConnection()

    def _check_leftover(self):
        if self._buf:
            # treat everything after the last newline as it's own line
            # this is important for things that never send a newline
            self._lines.add(self._buf.decode("utf8", "ignore"))
            self._buf = b""
            return self._check()
        else:
            return False
    def _check(self):
        for key, bad_lines in self.bad.items():
            if (self._lines&bad_lines) == bad_lines:
                self.deferred.callback(f"TCP banner ({key})")
                return True
        else:
            return False

class BannerChecker(object):
    tls = False
    def __init__(self, port, bad, send=""):
        self.port = port

        # data to send prior to banner reading
        self.send = send
        # convert {k: [v1,v2]} in to {k: set([v1,v2])}
        self.bad  = {k: set(v) for k, v in bad.items()}

    def check(self, scan, env):
        creator = protocol.ClientCreator(env.reactor, BannerProtocol,
                                         self.bad, self.send)
        if env.bind_address:
            bindAddress = (env.bind_address, 0)
        else:
            bindAddress = None

        # Disable the timeout here because our calling scanner should
        # cancel us just fine without it
        if self.tls:
            opt = ssl.CertificateOptions(verify=False)
            d = creator.connectSSL(scan.ip, self.port, opt, timeout=None,
                                   bindAddress=bindAddress)
        else:
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

class TLSBannerChecker(BannerChecker):
    tls = True
