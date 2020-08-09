# Copyright (c) 2010  Marien Zwart


"""DNS blacklist and similar checks."""

from __future__ import absolute_import, with_statement, division
from ipaddress  import ip_address

from twisted.internet import defer
from twisted.internet.abstract import isIPAddress
from twisted.internet.error import DNSLookupError
from twisted.names.error import DNSNameError

from . import util

class DNSBLChecker(object):

    def __init__(self, dnsbl, reasons):
        self.dnsbl = dnsbl
        self.reasons = reasons

    @defer.inlineCallbacks
    def check(self, scan, env):
        address_obj = ip_address(scan.ip)

        if address_obj.version == 6:
            address = reversed(address_obj.exploded.replace(":", ""))
        else:
            address = reversed(address_obj.exploded.split("."))

        query = '.'.join(list(address) + [self.dnsbl])

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
