# Copyright (c) 2010  Marien Zwart


"""Some utility code used exclusively by the tests."""


from twisted.internet import defer
from twisted.names import dns


class MockResolver(object):

    def __init__(self, hosts):
        self.hosts = dict(
            (name, dns.RRHeader(name=name,
                                payload=dns.Record_A(address=address)))
            for name, address in hosts.iteritems())

    def lookupAddress(self, name):
        try:
            return defer.succeed(([self.hosts[name]], [], []))
        except KeyError:
            return defer.succeed(([], [], []))
