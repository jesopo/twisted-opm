# Copyright (c) 2010  Marien Zwart


"""DNS blacklist and similar checks."""

from __future__ import absolute_import, with_statement, division
from ipaddress  import ip_address
import re

from twisted.internet import defer
from twisted.internet.abstract import isIPAddress
from twisted.internet.error import DNSLookupError
from twisted.names.error import DNSNameError
from twisted.names.client import createResolver

from . import util

class rDNSChecker(object):

    def __init__(self, bad):
        self.bad = [(re.compile(k, re.I), v) for k, v in bad.items()]

    @defer.inlineCallbacks
    def check(self, scan, env):
        query = ip_address(scan.ip).reverse_pointer
        try:
            result, _, _ = yield env.resolver.lookupPointer(query)
        except (DNSLookupError, DNSNameError):
            # XXX is this the right set of exceptions?
            defer.returnValue(None)
        else:
            # domain names should always be ascii, yeah?
            result = result[0].payload.name.name.decode("ascii")
            for pattern, description in self.bad:
                if pattern.fullmatch(result):
                    defer.returnValue(description)
                    break

class DNSBLChecker(object):

    def __init__(self, dnsbl, reasons, nameserver=None):
        self.dnsbl = dnsbl
        self.reasons = reasons

        if nameserver is not None:
            nameserver, _, nsport = nameserver.partition(":")
            self.resolver = createResolver([(nameserver, int(nsport or "53"))])
        else:
            self.resolver = None

    @defer.inlineCallbacks
    def check(self, scan, env):
        address_obj = ip_address(scan.ip)

        if address_obj.version == 6:
            address = reversed(address_obj.exploded.replace(":", ""))
        else:
            address = reversed(address_obj.exploded.split("."))

        query = '.'.join(list(address) + [self.dnsbl])

        resolver = (self.resolver or env.resolver)
        try:
            result = yield util.getV4HostByName(resolver, query)
        except DNSNameError:
            # XXX util.getV4HostByName should probably catch this instead.
            result = None

        if result is None:
            defer.returnValue(None)

        reason = int(result.rsplit('.', 1)[1])
        defer.returnValue(self.reasons.get(reason,
                                           'Unknown reason %d' % (reason,)))
