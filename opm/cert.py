import re
from twisted.internet import defer, error, protocol, ssl, interfaces
from zope.interface   import directlyProvides

from cryptography          import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.hazmat.backends   import default_backend
from cryptography.hazmat.primitives import hashes

CERT_KEYS = [
    ("cn", NameOID.COMMON_NAME),
    ("on", NameOID.ORGANIZATION_NAME)
]

def _cert_dict(items):
    return {i.oid: i.value for i in items}

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
            cert       = x509.load_pem_x509_certificate(
                cert.dumpPEM(), default_backend()
            )
            values.append(("sha1", cert.fingerprint(hashes.SHA1()).hex()))

            subject    = _cert_dict(list(cert.subject))
            issuer     = _cert_dict(list(cert.issuer))
            extensions = _cert_dict(list(cert.extensions))

            for match_key, oid in CERT_KEYS:
                if oid in subject:
                    values.append((f's{match_key}', subject[oid]))
                if oid in issuer:
                    values.append((f'i{match_key}', issuer[oid]))

            sans = extensions.get(ExtensionOID.SUBJECT_ALTERNATIVE_NAME, [])
            for san in sans:
                values.append(("san", san.value))

        for pattern, description in self.bad:
            for k, v in values:
                key = f'{k}:{v}'
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
