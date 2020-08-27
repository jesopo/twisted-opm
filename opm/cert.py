import re
from twisted.internet import defer, error, protocol, ssl, interfaces
from zope.interface   import directlyProvides

CERT_KEYS = [
    ("CN", "cn"),
    ("O",  "on")
]

def _byte_dict(items):
    return {k.decode("utf8"): v.decode("utf8") for k, v in items}

class CertificateProtocol(protocol.Protocol):
    def __init__(self, bad):
        self.bad = bad
        directlyProvides(self, interfaces.IHandshakeListener)

    def connectionMade(self):
        self.deferred = defer.Deferred(self.cancel)
    def cancel(self, defer):
        if defer is self.deferred:
            self.deferred = None
            self.transport.loseConnection()
    def connectionLost(self, reason):
        if self.deferred is not None:
            self.deferred.callback(None)

    def handshakeCompleted(self):
        values  = []
        cert    = ssl.Certificate(self.transport.getPeerCertificate())

        if cert is not None:
            cert    = cert.original
            subject = _byte_dict(cert.get_subject().get_components())
            issuer  = _byte_dict(cert.get_issuer().get_components())

            for cert_key, match_key in CERT_KEYS:
                if cert_key in subject:
                    values.append((f's{match_key}', subject[cert_key]))
                if cert_key in issuer:
                    values.append((f'i{match_key}', issuer[cert_key]))

            for i in range(cert.get_extension_count()):
                ext = cert.get_extension(i)
                if ext.get_short_name() == b"subjectAltName":
                    sans = ext.get_data()[4:].split(b"\x82\x18")
                    for san in sans:
                        values.append(("san", san.decode("ascii")))

        for pattern, description in self.bad:
            for k, v in values:
                key = f'{k}:{v.lower()}'
                if pattern.fullmatch(key):
                    d = self.deferred
                    self.deferred = None
                    d.callback(f"{description} ({key})")
                    break

        self.transport.loseConnection()

class CertificateChecker(object):
    def __init__(self, port, bad):
        self.port = port
        # convert {k:v} to [(regex(k), v)]
        self.bad  = [(re.compile(k, re.I), v) for k, v in bad.items()]

    def check(self, scan, env):
        options = ssl.CertificateOptions(verify=False)
        creator = protocol.ClientCreator(env.reactor, CertificateProtocol,
                                         self.bad)

        if env.bind_address:
            bindAddress = (env.bind_address, 0)
        else:
            bindAddress = None
        # Disable the timeout here because our calling scanner should
        # cancel us just fine without it:
        d = creator.connectSSL(scan.ip, self.port, options, timeout=None,
                               bindAddress=bindAddress)

        def connected(proto):
            return proto.deferred
        def connectFailed(fail):
            # If we could not connect for some sane reason it's just
            # not a proxy. Let unknown errors propagate though.
            fail.trap(error.ConnectionRefusedError, error.TCPTimedOutError)
        d.addCallbacks(connected, connectFailed)

        return d
