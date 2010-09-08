# Copyright (c) 2010  Marien Zwart


"""Tests for the irc presence."""


from __future__ import absolute_import, with_statement, division

from twisted.trial import unittest
from twisted.python import failure
from twisted.internet import task, defer
from twisted.test import proto_helpers

from .. import ircpresence, scanner


class Scanner(object):

    def __init__(self, pools):
        self.pools = pools
        self.scans = {}
        self.d = defer.Deferred()

    def scan(self, ip=None, host=None, scansets=None, errhandler=None):
        self.ip = ip
        self.host = host
        self.scansets = set(scansets if scansets is not None else [])
        self.errhandler = errhandler
        missing = self.scansets - set(['default'])
        if missing:
            raise scanner.UnknownScanset(missing.pop())
        if host == 'missing':
            raise scanner.DNSNameError()
        return self.d


class ClientTest(unittest.TestCase):

    def initialize(self, **kwargs):
        self.transport = proto_helpers.StringTransport()
        self.clock = task.Clock()
        # Because the Client assumes timestamp 0 is well in the past
        self.clock.advance(9000)
        self.scanner = Scanner(dict(pool2=defer.DeferredSemaphore(2),
                                    pool3=defer.DeferredSemaphore(3)))
        self.factory = ircpresence.Factory(
            'anick', '#achannel', self.scanner,
            {'nick!user@host': ['default'], 'other!*@*': ['missing']},
            **kwargs)
        self.proto = self.factory.buildProtocol(None)
        # Allow bursting lots of messages:
        self.proto.messageBurst = 200
        self.proto.clock = self.clock
        self.proto.transport = self.transport
        self.proto.connectionMade()

    def connectIRC(self):
        self.assertReceived('NICK anick\r\n'
                            'USER anick foo bar :txOPM\r\n')
        self.proto.dataReceived(':ser.ver 001 anick :Welcome\r\n')
        self.assertReceived('JOIN #achannel\r\n')

    def assertReceived(self, data):
        self.assertEqual(data, self.transport.value())
        self.transport.clear()

    def testConnect(self):
        self.initialize(opername='oname', operpass='opass', away='very far',
                        opermode='+g', onconnectmsgs=[['nickserv', 'yo yo']])
        self.assertReceived('NICK anick\r\n'
                            'USER anick foo bar :txOPM\r\n')
        self.assertIdentical(None, self.factory.bot)
        self.proto.dataReceived(
            ':ser.ver 001 anick :Welcome to the network\r\n')
        self.assertReceived('PRIVMSG nickserv :yo yo\r\n'
                            'OPER oname opass\r\n'
                            'AWAY :very far\r\n'
                            'JOIN #achannel\r\n')
        self.assertIdentical(self.proto, self.factory.bot)
        self.proto.dataReceived(':ser.ver 381 anick :Now you are an oper\r\n')
        self.assertReceived('MODE anick +g\r\n')

        self.proto.connectionLost(None)
        self.assertIdentical(self.factory.bot, None)

    def testConnectNoticeNoRegex(self):
        self.initialize()
        self.connectIRC()

        self.proto.dataReceived(
            ':ser.ver NOTICE * :-- nick (user@host) [1.2.3.4]\r\n')
        self.assertReceived('')

    def initializeForNotice(self):
        self.initialize(
            connregex=r'-- (?P<nick>[^ ]+) '
            '\((?P<user>[^@]+)@(?P<host>[^)]+)\) \[(?P<ip>[0-9.]+)\]',
            klinetemplate='KILL it with fire')
        self.connectIRC()

    def testNonServerNotice(self):
        self.initializeForNotice()
        self.proto.dataReceived(
            ':foo!bar@baz NOTICE anick :-- nick (user@host) [1.2.3.4]\r\n')
        self.assertReceived('')

    def testNonMatchingServerNotice(self):
        self.initializeForNotice()
        self.proto.dataReceived(':ser.ver NOTICE * :blah\r\n')
        self.assertReceived('')

    def testMatchingServerNoticeGood(self):
        self.initializeForNotice()
        self.proto.dataReceived(
            ':ser.ver NOTICE * :-- nick (user@host) [1.2.3.4]\r\n')
        self.assertReceived('')

        self.assertEqual('1.2.3.4', self.scanner.ip)
        self.assertEqual('host', self.scanner.host)
        self.assertEqual(set(['default']), self.scanner.scansets)

        self.scanner.d.callback(None)
        self.assertReceived('')

    def testMatchingServerNoticeBad(self):
        self.initializeForNotice()
        self.proto.dataReceived(
            ':ser.ver NOTICE * :-- nick (user@host) [1.2.3.4]\r\n')
        self.assertReceived('')

        self.scanner.d.callback('naughty')
        self.assertReceived(
            'KILL it with fire\r\n'
            'PRIVMSG #achannel :BAD: nick!user@host (naughty)\r\n')

    def testOffChannelPrivmsg(self):
        self.initialize()
        self.connectIRC()
        self.proto.dataReceived(
            ':foo!bar@baz PRIVMSG anick :anick: help\r\n')
        self.assertReceived('')

    def testWrongChannelPrivmsg(self):
        self.initialize()
        self.connectIRC()
        self.proto.dataReceived(
            ':foo!bar@baz PRIVMSG #kchan :anick: help\r\n')
        self.assertReceived('')

    def testWrongTargetPrivmsg(self):
        self.initialize()
        self.connectIRC()
        self.proto.dataReceived(
            ':foo!bar@baz PRIVMSG #achannel :notme: help\r\n')
        self.assertReceived('')

    def testNoArgsPrivmsg(self):
        self.initialize()
        self.connectIRC()
        self.proto.dataReceived(
            ':foo!bar@baz PRIVMSG #achannel :anick: \r\n')
        self.assertReceived('')

    def runCommand(self, command, initialize=True):
        if initialize:
            self.initialize()
        self.connectIRC()
        self.proto.dataReceived(
            ':foo!bar@baz PRIVMSG #achannel :anick: %s\r\n' % (command,))

    def testGoodChannelPrivmsg(self):
        self.runCommand('help')
        self.assertReceived(
            'PRIVMSG #achannel :commands: check stats help\r\n')

    def testStats(self):
        self.initialize()
        pool2 = self.scanner.pools['pool2']
        pool2.acquire()
        pool2.acquire()
        pool2.acquire()
        self.runCommand('stats', initialize=False)
        self.assertReceived(
            'PRIVMSG #achannel :pool2: 1 queued\r\n'
            'PRIVMSG #achannel :pool3: 3 free\r\n'
            'PRIVMSG #achannel :0 checks in progress\r\n')

    def testCheckNothing(self):
        self.runCommand('check')
        self.assertReceived('PRIVMSG #achannel :check what?\r\n')

    def testCheckDefaultHost(self):
        self.runCommand('check host')
        self.assertReceived('')
        self.assertEqual('host', self.scanner.host)
        self.assertIdentical(None, self.scanner.ip)
        self.assertEqual(set(['default']), self.scanner.scansets)

    def testCheckDefaultIP(self):
        self.runCommand('check 1.2.3.4')
        self.assertReceived('')
        self.assertEqual('1.2.3.4', self.scanner.ip)
        self.assertIdentical(None, self.scanner.host)
        self.assertEqual(set(['default']), self.scanner.scansets)

    def testErrHandler(self):
        self.runCommand('check 1.2.3.4')
        self.assertReceived('')
        self.scanner.errhandler(failure.Failure(ValueError('kablam')))
        self.assertReceived('PRIVMSG #achannel :failure: kablam\r\n')

    def testUnknownScanset(self):
        self.runCommand('check host rabies')
        self.assertReceived('PRIVMSG #achannel :unknown scanset rabies\r\n')

    def testHostMissing(self):
        self.runCommand('check missing')
        self.assertReceived('PRIVMSG #achannel :missing did not resolve\r\n')

    def testGood(self):
        self.runCommand('check host')
        self.assertReceived('')
        self.scanner.d.callback(None)
        self.assertReceived('PRIVMSG #achannel :host is clean\r\n')

    def testBad(self):
        self.runCommand('check host')
        self.assertReceived('')
        self.scanner.d.callback('naughty')
        self.assertReceived('PRIVMSG #achannel :host is bad: naughty\r\n')

    def testThrottle(self):
        self.initialize(away='away', opername='name', operpass='pass')
        self.proto.messageBurst = 4
        self.assertReceived('NICK anick\r\n'
                            'USER anick foo bar :txOPM\r\n')
        self.proto.dataReceived(':ser.ver 001 anick :Welcome\r\n')
        self.assertReceived('OPER name pass\r\n')
        self.clock.advance(2)
        self.assertReceived('AWAY :away\r\n')
        self.failUnless(self.clock.getDelayedCalls())
        self.proto.connectionLost(None)
        self.failIf(self.clock.getDelayedCalls())
