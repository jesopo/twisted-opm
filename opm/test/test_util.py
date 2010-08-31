# Copyright (c) 2010  Marien Zwart


from __future__ import absolute_import, with_statement, division

from twisted.trial import unittest

from . import testutils
from .. import util


class ResolverTest(unittest.TestCase):

    def setUp(self):
        self.resolver = testutils.MockResolver(dict(thehost='1.2.3.4'))

    def testGetV4HostByNameSuccess(self):
        d = util.getV4HostByName(self.resolver, 'thehost')
        self.assertEqual('1.2.3.4', d.result)

    def testGetV4HostByNameFailure(self):
        d = util.getV4HostByName(self.resolver, 'notthehost')
        self.assertIdentical(None, d.result)
