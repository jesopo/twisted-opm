import hashlib
from twisted.internet  import defer, error, protocol, interfaces, ssl
from twisted.protocols import basic

HTTP_GET = "GET / HTTP/1.0\r\n\r\n"

class HTTPBodyProtocol(protocol.Protocol):
    def __init__(self, bad, send):
        self.send  = send
        self.bad   = bad

        self._buff = b""
        self._head = 0
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
            while (self._head <= 20 and     # no more than 20 headers
                    data.find(b"\n") > -1): # do we still have newlines?

                self._head += 1
                line, data = data.split(b"\n", 1)
                line = line.strip(b"\r").lower()

                if not line:
                    self._body = True
                    break
                elif line.startswith(b"content-length: "):
                    _, clen = line.split(b": ", 1)
                    try:
                        self._clen = int(clen)
                    except ValueError:
                        # well thats not a number is it
                        self.transport.loseConnection()
                        return

        self._buff = data

        if (self._body and
                self.deferred is not None and   # not matched yet
                len(self._buff) >= self._clen): # we've got enough body

            body = self._buff[:self._clen]
            hash = hashlib.sha1(body).hexdigest()
            self._check(hash)

            self.transport.loseConnection()

    def _check(self, hash):
        if hash in self.bad:
            description = self.bad[hash]
            d = self.deferred
            d.callback(f"{description} ({hash})")
            self.deferred = None

class HTTPBodyChecker(object):
    tls = False
    def __init__(self, port, bad, send=HTTP_GET):
        self.port = port

        # data to send, usually GET / etc.
        self.send = send
        # {sha1: name} mapping of who's bad
        self.bad  = bad

    def check(self, scan, env):
        creator = protocol.ClientCreator(env.reactor, HTTPBodyProtocol,
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

class HTTPSBodyChecker(HTTPBodyChecker):
    tls = True
