# Copyright (c) 2010  Marien Zwart


from __future__ import absolute_import, with_statement, division

from twisted.trial import unittest
from twisted.python import log
from twisted.internet import task, defer
from twisted.names.error import DNSNameError

from . import testutils
from .. import scanner


def sync_bad(scan):
    return 'bad'


class TestError(ValueError):
    """Caught by tests."""


class ScanTest(unittest.TestCase):

    def setUp(self):
        self.clock = task.Clock()
        self.scan = scanner.Scan(self.clock, None)
        self.onepool = defer.DeferredSemaphore(1)
        self.hugepool = defer.DeferredSemaphore(9000)

    def testNoChecks(self):
        d = self.scan.getResult()
        self.failIf(d.called)
        self.scan.start()
        self.failUnless(d.called)
        self.assertIdentical(None, d.result)

    def testSyncBad(self):
        d = self.scan.getResult()
        self.scan.addCheck(sync_bad, self.onepool, 1)
        self.assertEqual('bad', d.result)
        self.scan.addCheck(self.fail, self.hugepool, 1)

    def testAlreadyBadReturnsSynchronously(self):
        self.scan.addCheck(sync_bad, self.onepool, 1)
        d = self.scan.getResult()
        self.assertEqual('bad', d.result)

    def testAlreadyGoodReturnsSynchronously(self):
        self.scan.start()
        d = self.scan.getResult()
        self.failUnless(d.called)
        self.assertIdentical(None, d.result)

    def testDuplicateCheckIgnored(self):
        self.count = 0
        def add(scan):
            self.count += 1

        self.scan.addCheck(add, self.hugepool, 1)
        self.assertEqual(1, self.count)
        self.scan.addCheck(add, self.hugepool, 1)
        self.assertEqual(1, self.count)

    def testPendingCheckCancelled(self):
        d = defer.Deferred()
        def never(scan):
            return d

        self.scan.addCheck(never, self.hugepool, 1)
        self.scan.addCheck(sync_bad, self.hugepool, 1)
        self.failUnless(d.called)

    def testASyncBad(self):
        check_d = defer.Deferred()
        def bad(scan):
            return check_d

        self.scan.addCheck(bad, self.onepool, 1)
        d = self.scan.getResult()
        self.scan.start()
        self.failIf(d.called)
        check_d.callback('bad')
        self.assertEqual('bad', d.result)

    def testSyncFailure(self):
        def fail(scan):
            raise TestError()

        # HACK: do not log the failure.
        self.scan.errhandlers = []

        self.scan.addCheck(fail, self.onepool, 1)
        d = self.scan.getResult()
        self.scan.start()
        self.failUnless(d.called)
        self.assertIdentical(None, d.result)

    def testASyncFailure(self):
        check_d = defer.Deferred()
        def fail(scan):
            return check_d

        # HACK: do not log the failure.
        self.scan.errhandlers = []

        self.scan.addCheck(fail, self.onepool, 1)
        d = self.scan.getResult()
        self.scan.start()
        self.failIf(d.called)
        check_d.errback(TestError())
        self.failUnless(d.called)
        self.assertIdentical(None, d.result)

    def testASyncGood(self):
        check_d = defer.Deferred()
        def good(self):
            return check_d

        self.scan.addCheck(good, self.onepool, 1)
        d = self.scan.getResult()
        self.scan.start()
        self.failIf(d.called)
        check_d.callback(None)
        self.failUnless(d.called)
        self.assertIdentical(None, d.result)

    def testErrHandler(self):
        def fail(scan):
            raise TestError()

        failures = []
        def errhandler(fail):
            failures.append(fail)
        scan = scanner.Scan(self.clock, None, errhandler=errhandler)
        self.failUnless(errhandler in scan.errhandlers)
        scan.errhandlers.remove(log.err)

        scan.addCheck(fail, self.onepool, 1)

        self.assertEqual(1, len(failures))
        failures[0].trap(TestError)


class ScannerTest(unittest.TestCase):

    def setUp(self):
        self.clock = task.Clock()
        self.resolver = testutils.MockResolver(dict(thehost='1.2.3.4'))
        self.pools = dict(onepool=1)
        # HACK: rely on the fact we can get away with adding to this
        # after constructing a scanner.
        self.scansets = {}
        self.scanner = scanner.Scanner(
            self.clock, self.resolver, self.pools, self.scansets, {})

    def testApiSanity(self):
        self.assertFailure(self.scanner.scan(), TypeError)

    def testEnvironment(self):
        def checkEnvironment(scan, env):
            self.assertIdentical(self.resolver, env.resolver)
            self.assertIdentical(self.clock, env.reactor)
        self.scansets['default'] = [(1, 'onepool', checkEnvironment)]

        self.scanner.scan(ip='127.0.0.1', scansets=['default'])

    def testNoResolveIfNoScansets(self):
        self.scanner.scan(host='ignored', scansets=())

    def testResolveFailure(self):
        self.scansets['default'] = [(1, 'onepool', sync_bad)]
        self.assertFailure(
            self.scanner.scan(host='notthehost', scansets=['default']),
            DNSNameError)

    def testResolve(self):
        checked = []
        def check(scan, env):
            self.assertEqual('1.2.3.4', scan.ip)
            checked.append(True)

        self.scansets['default'] = [(1, 'onepool', check)]
        self.scanner.scan(host='thehost', scansets=['default'])

        self.failUnless(checked)

    def testReuse(self):
        check_d = defer.Deferred()
        self.count = 0
        def check(scan, env):
            self.count += 1
            return check_d

        self.scansets['default'] = [(1, 'onepool', check)]
        d = self.scanner.scan(ip='127.0.0.1', scansets=['default'])
        d2 = self.scanner.scan(ip='127.0.0.1', scansets=['default'])

        self.assertEqual(1, self.count)
        self.failIf(d.called)
        self.failIf(d2.called)
        check_d.callback(None)

        self.failUnless(d.called)
        self.failUnless(d2.called)

    def testErrhandlerOnReuse(self):
        failures = []
        check_d = defer.Deferred()
        def check(scan, env):
            return check_d

        self.scansets['default'] = [(1, 'onepool', check)]

        self.scanner.scan(ip='127.0.0.1', scansets=['default'])
        self.scanner.scan(ip='127.0.0.1', scansets=['default'],
                          errhandler=failures.append)

        # HACK: remove standard error logging
        self.scanner.scans['127.0.0.1'].errhandlers.remove(log.err)

        check_d.errback(TestError())
        self.assertEqual(1, len(failures))

    def testUnknownScanset(self):
        self.assertFailure(self.scanner.scan(ip='127.0.0.1', scansets=['no']),
                           scanner.UnknownScanset)
