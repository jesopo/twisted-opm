import hashlib
from twisted.internet  import defer, error, protocol, interfaces, ssl
from twisted.protocols import basic

HTTP_GET = "GET / HTTP/1.0\r\n\r\n"

STABLE_HEADERS = set([
    b"content-type",
    b"cache-control",
    b"referrer-policy",
    b"connection",
    b"server"
])

class HTTPProtocol(protocol.Protocol):
    def __init__(self, bad, send):
        self.send  = send
        self.bad   = bad

        self._buff = b""
        self._head = []
        self._body = False
        self._clen = -1


    def connectionMade(self):
        self.deferred = defer.Deferred(self.cancel)
        if self.send:
            self.transport.write(self.send.encode("utf8"))
    def cancel(self, defer):
        if defer is self.deferred:
            self.deferred = None
            self.transport.loseConnection()
    def connectionLost(self, reason):
        if self.deferred is not None:
            self.deferred.callback(None)

    def dataReceived(self, data):
        data = self._buff + data

        if not self._body:
            while (len(self._head) <= 20 and # no more than 20 headers
                    data.find(b"\n") > -1):  # do we still have newlines?

                line, data = data.replace(b"\r", b'').split(b"\n", 1)

                if not line:
                    self._body = True
                    break
                elif not self._head:
                    # probably "HTTP/1.1 200 OK" or so
                    self._head.append((None, line))
                elif b": " in line:
                    # we've got a key:value header
                    key, value = line.split(b": ", 1)
                    key = key.lower()
                    self._head.append((key, value))

                    if key == b"content-length":
                        try:
                            self._clen = int(value)
                        except ValueError:
                            # well thats not a number is it
                            self.transport.loseConnection()
                            return

        self._buff = data

        if (self._body and
                self.deferred is not None and   # not matched yet
                len(self._buff) >= self._clen): # we've got enough body

            if not self._check():
                self.deferred.callback(None)
            self.deferred = None
            self.transport.loseConnection()

    def _check(self):
        head = b""
        for key, value in self._head:
            if key is None:
                # probably "HTTP/1.1 200 OK" or so
                head += b"%b\r\n" % value
            elif key in STABLE_HEADERS:
                # key:value header
                head += b"%b: %b\r\n" % (key, value)

        body = self._buff[:self._clen]
        hashes = set([
            hashlib.sha1(body).hexdigest(),
            hashlib.sha1(head).hexdigest(),
            hashlib.sha1(b"%b\r\n%b" % (head, body)).hexdigest()
        ])

        match = hashes&set(self.bad.keys())
        if match:
            hash = list(match)[0]
            description = self.bad[hash]
            self.deferred.callback(f"{description} ({hash})")
            return True
        else:
            return False

class HTTPChecker(object):
    tls = False
    def __init__(self, port, bad, send=HTTP_GET):
        self.port = port

        # data to send, usually GET / etc.
        self.send = send
        # {sha1: name} mapping of who's bad
        self.bad  = bad

    def check(self, scan, env):
        creator = protocol.ClientCreator(env.reactor, HTTPProtocol,
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

class HTTPSChecker(HTTPChecker):
    tls = True
