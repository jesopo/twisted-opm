# Copyright (c) 2010  Marien Zwart


from __future__ import absolute_import, with_statement, division

from twisted.trial import unittest

from .. import plugin
from . import plugins

def identity(*args, **kwargs):
    return args, kwargs



class PluginTest(unittest.TestCase):

    def testGetCheckerFactories(self):
        self.failUnless(list(plugin.getCheckerFactories()))

    def testCheckerFactory(self):
        factory = plugin.CheckerFactory('aname',
                                        'opm.test.test_plugin.identity')

        self.assertEqual(((1,), dict(a=2)), factory(1, a=2))

    def testDuplicate(self):
        self.assertRaises(KeyError, plugin.getCheckerFactories, plugins)
