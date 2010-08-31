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
