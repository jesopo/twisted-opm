# Copyright (c) 2010  Marien Zwart


"""Checker plugin infrastructure."""


from __future__ import absolute_import, with_statement, division

from zope.interface import Interface, Attribute, implementer

from twisted.python.reflect import namedAny
from twisted import plugin

from . import plugins


class ICheckerFactory(Interface):

    """Call something implementing this to get a checker."""

    name = Attribute('name')

@implementer(ICheckerFactory, plugin.IPlugin)
class CheckerFactory(object):

    def __init__(self, name, qname):
        self.name = name
        self.qname = qname

    def __call__(self, *args, **kwargs):
        return namedAny(self.qname)(*args, **kwargs)


def getCheckerFactories(package=plugins):
    d = {}
    for plug in plugin.getPlugins(ICheckerFactory, package):
        if plug.name in d:
            raise KeyError('duplicate provider for %s' % (plug.name,))
        d[plug.name] = plug
    return d
