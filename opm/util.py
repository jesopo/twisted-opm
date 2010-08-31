# Copyright (c) 2010  Marien Zwart


"""Utility code."""


from __future__ import absolute_import, with_statement, division


from twisted.internet import defer
from twisted.names import common, dns


@defer.inlineCallbacks
def getV4HostByName(resolver, name):
    """Return a deferred yielding a single ipv4 address."""
    answers, auth, add = yield resolver.lookupAddress(name)
    # This is sometimes (but not normally) a deferred.
    # defer.returnValue(d) is an AssertionError.
    result = yield defer.maybeDeferred(
        common.extractRecord, resolver, dns.Name(name), answers)
    defer.returnValue(result)
