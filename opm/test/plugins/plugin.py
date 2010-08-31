# Copyright (c) 2010  Marien Zwart


"""Test plugins loaded by test_plugin."""


from __future__ import absolute_import, with_statement, division

from ... import plugin

one = plugin.CheckerFactory('duplicate', 'opm.test.test_plugin.identity')
two = plugin.CheckerFactory('duplicate', 'opm.test.test_plugin.identity')
