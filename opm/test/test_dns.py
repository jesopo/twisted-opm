# Copyright (c) 2010  Marien Zwart


from __future__ import absolute_import, with_statement, division

from twisted.trial import unittest
from twisted.internet import defer
from twisted.internet.error import DNSLookupError

from . import testutils
from .. import dns, scanner


class MockResolver(testutils.MockResolver):

    def getHostByName(self, host):
        try:
            return self.hosts[host]
        except KeyError:
            raise DNSLookupError()


class MockScan(object):

    def __init__(self, ip):
        self.ip = ip


class TorTestByIP(unittest.TestCase):

    def setUp(self):
        self.resolver = MockResolver({
                'thehost': '1.2.3.4',
                'notthehost': '9.9.9.9',
                '8.7.6.5.42.4.3.2.1.ip-port.exitlist.torproject.org':
                    '127.0.0.1',
                })
        self.env = scanner.ScanEnvironment(reactor=None,
                                           resolver=self.resolver)
        self.scan = MockScan('5.6.7.8')

    @defer.inlineCallbacks
    def testTorIP(self):
        checker = dns.TorChecker('1.2.3.4', 42)
        result = yield checker.check(self.scan, self.env)
        self.assertEqual('tor exit node (1.2.3.4:42)', result)

    @defer.inlineCallbacks
    def testNonTorIP(self):
        checker = dns.TorChecker('4.3.2.1', 42)
        result = yield checker.check(self.scan, self.env)
        self.assertIdentical(None, result)

    @defer.inlineCallbacks
    def testTorHost(self):
        checker = dns.TorChecker('thehost', 42)
        result = yield checker.check(self.scan, self.env)
        self.assertEqual('tor exit node (thehost:42)', result)

    @defer.inlineCallbacks
    def testNonTorHost(self):
        checker = dns.TorChecker('notthehost', 42)
        result = yield checker.check(self.scan, self.env)
        self.assertIdentical(None, result)


class DNSBLTest(unittest.TestCase):

    def setUp(self):
        self.resolver = MockResolver({
                '8.7.6.5.dnsbl.it': '127.0.0.4',
                })
        self.env = scanner.ScanEnvironment(reactor=None,
                                           resolver=self.resolver)
        self.scan = MockScan('5.6.7.8')
        self.scan2 = MockScan('1.2.3.4')

    @defer.inlineCallbacks
    def testBadIPKnownReason(self):
        checker = dns.DNSBLChecker('dnsbl.it', {4: 'Naughty'})
        result = yield checker.check(self.scan, self.env)
        self.assertEqual('Naughty', result)

    @defer.inlineCallbacks
    def testBadIPUnknownReason(self):
        checker = dns.DNSBLChecker('dnsbl.it', {})
        result = yield checker.check(self.scan, self.env)
        self.assertEqual('Unknown reason 4', result)

    @defer.inlineCallbacks
    def testGoodIP(self):
        checker = dns.DNSBLChecker('dnsbl.it', {})
        result = yield checker.check(self.scan2, self.env)
        self.assertIdentical(None, result)
