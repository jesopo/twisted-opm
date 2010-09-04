# Copyright (c) 2010  Marien Zwart


"""DNS blacklist and similar checks."""


from __future__ import absolute_import, with_statement, division

from twisted.internet import defer
from twisted.internet.abstract import isIPAddress
from twisted.internet.error import DNSLookupError
from twisted.names.error import DNSNameError

from . import util


class TorChecker(object):

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self._query = None
        if isIPAddress(host):
            self._setIP(host)

    def _setIP(self, ip):
        self._query = '.%s.%s.ip-port.exitlist.torproject.org' % (
            self.port, '.'.join(reversed(ip.split('.'))))

    @defer.inlineCallbacks
    def check(self, scan, env):
        if self._query is None:
            ip = yield util.getV4HostByName(env.resolver, self.host)
            self._setIP(ip)

        query = '.'.join(reversed(scan.ip.split('.'))) + self._query
        try:
            yield env.resolver.getHostByName(query)
        except (DNSLookupError, DNSNameError):
            # XXX is this the right set of exceptions?
            defer.returnValue(None)
        else:
            defer.returnValue('tor exit node (%s:%s)' %
                              (self.host, self.port))


class DNSBLChecker(object):

    def __init__(self, dnsbl, reasons):
        self.dnsbl = dnsbl
        self.reasons = reasons

    @defer.inlineCallbacks
    def check(self, scan, env):
        query = '.'.join(list(reversed(scan.ip.split('.'))) + [self.dnsbl])
        try:
            result = yield util.getV4HostByName(env.resolver, query)
        except DNSNameError:
            # XXX util.getV4HostByName should probably catch this instead.
            result = None

        if result is None:
            defer.returnValue(None)

        reason = int(result.rsplit('.', 1)[1])
        defer.returnValue(self.reasons.get(reason,
                                           'Unknown reason %d' % (reason,)))
