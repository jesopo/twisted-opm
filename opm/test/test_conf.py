# Copyright (c) 2010  Marien Zwart


from __future__ import absolute_import, with_statement, division

import os.path as osp

from twisted.python import usage
from twisted.trial import unittest
from twisted.names.client import getResolver

from .. import conf


class OptionsTest(unittest.TestCase):

    def setUp(self):
        self.options = conf.Options()

    def testMissing(self):
        self.assertRaises(usage.error,
                          self.options.parseOptions, ['/does/not/exist'])

    def testParse(self):
        self.options.parseOptions([osp.join(osp.dirname(__file__),
                                            'parsetest.conf')])
        self.assertEqual(dict(nonsense=['look', 'a', 'test']),
                         self.options['conf'])

    def testResourceCheck(self):
        soft_limit, hard_limit = conf.resource.getrlimit(
            conf.resource.RLIMIT_NOFILE)
        self.options['conf'] = dict(pools=dict(one=soft_limit,
                                               two=hard_limit))
        self.assertRaises(usage.error, self.options.postOptions)

    if conf.resource is None:
        testResourceCheck.skip = 'no resource module' # pragma: no cover


# These are very rudimentary but it seems possible this will mostly be
# rewritten to support rehashing at some point anyway.


def _makeService(**kwargs):
    return conf.makeService({'force-select': True, 'keep-resolver': True,
                             'irc-log': False, 'conf': kwargs})

class ServiceTest(unittest.TestCase):

    def tearDown(self):
        # XXX HACK
        resolver = getResolver()
        call = resolver.resolvers[-1]._parseCall
        if call.active():
            call.cancel()

    def testSimplestService(self):
        serv = _makeService(scansets=dict(), pools=dict())
        self.failUnless(serv)

    def testIrcService(self):
        serv = _makeService(
            scansets=dict(), pools=dict(),
            irc=dict(anet=dict(
                    host='127.0.0.1', port=6667,
                    nick='opm', channel='#opm',
                    )))
        self.failUnless(serv)

    def testScanset(self):
        serv = _makeService(
            pools={}, scansets=dict(default=dict(timeout=3, protocols=[
                        ['dns', 'tor', 'localhost', 6667]])))
        self.failUnless(serv)
