# Copyright (c) 2010  Marien Zwart


"""IRC client listening for connections and commands.

This is all pretty ad-hoc and terrible.
"""


from __future__ import absolute_import, with_statement, division

import re
import fnmatch

from twisted.python import log
from twisted.internet import protocol, defer
from twisted.internet.abstract import isIPAddress
from twisted.words.protocols import irc
from twisted.names.error import DNSNameError

from . import scanner


class Client(irc.IRCClient):

    clock = None

    messagePenalty = 2 # seconds
    messageBurst = 10 # seconds

    # Defaults to None which kind of sucks.
    realname = 'txOPM'

    def connectionMade(self):
        self.nickname = self.factory.nickname
        self.password = self.factory.password
        if self.clock is None: # pragma: no cover
            from twisted.internet import reactor
            self.clock = reactor
        self.messageTimer = 0
        irc.IRCClient.connectionMade(self)

    def sendLine(self, line):
        # Overridden to do rfc1459-style rate limiting.
        self._queue.append(line)
        if not self._queueEmptying:
            self._sendLines()

    def _sendLines(self):
        now = self.clock.seconds()
        if self.messageTimer < now:
            self.messageTimer = now

        while self._queue and self.messageTimer < now + self.messageBurst:
            self._reallySendLine(self._queue.pop(0))
            self.messageTimer += self.messagePenalty

        if self._queue:
            self._queueEmptying = self.clock.callLater(
                self.messageTimer - now - self.messageBurst, self._sendLines)
        else:
            self._queueEmptying = None

    def oper(self, name, password):
        self.sendLine('OPER %s %s' % (name, password))

    def signedOn(self):
        if self.factory.opername and self.factory.operpass:
            self.oper(self.factory.opername, self.factory.operpass)
        if self.factory.away:
            self.away(self.factory.away)
        self.join(self.factory.channel)
        self.factory.bot = self
        self.factory.resetDelay()

    def irc_RPL_YOUREOPER(self, prefix, params):
        # nick, message = params
        if self.factory.opermode:
            # The IRCClient "mode" method sucks, bypass it
            self.sendLine(
                'MODE %s %s' % (self.nickname, self.factory.opermode))

    def connectionLost(self, reason):
        self.factory.bot = None
        return irc.IRCClient.connectionLost(self, reason)

    @defer.inlineCallbacks
    def noticed(self, user, channel, message):
        # We only care about notices from the server, not from users.
        # Users have a hostmask as "user", servers do not.
        if '!' in user:
            return

        if self.factory.connregex is None:
            return

        match = self.factory.connregex.match(message)
        if match is None:
            return

        d = match.groupdict()

        masks = set()
        if 'ip' in d:
            masks.add('%s!%s@%s' % (d['nick'], d['user'], d['ip']))
        if 'host' in d:
            masks.add('%s!%s@%s' % (d['nick'], d['user'], d['host']))
        masks = list(masks)

        scansets = set()
        for mask, pattern, sets in self.factory.masks:
            for hostmask in masks:
                if pattern.match(hostmask) is not None:
                    scansets.update(sets)

        log.msg('Scanning %r on scanners %s' % (masks, ' '.join(scansets)))
        result = yield self.factory.scanner.scan(ip=d.get('ip'),
                                                 host=d.get('host'),
                                                 scansets=scansets)
        if result is not None:
            if self.factory.klinetemplate is not None:
                d['reason'] = result
                self.sendLine(self.factory.klinetemplate % d)
            log.msg('KILL %r for %s' % (masks, result))
        else:
            log.msg('GOOD %r' % (masks,))

    @defer.inlineCallbacks
    def privmsg(self, user, channel, message):
        # We use access to our channel as access control.
        # Private messages are rejected.
        if channel != self.factory.channel:
            return

        if not message.startswith(
            tuple(self.nickname + suffix
                  for suffix in (' ', ': ', ', ', '; '))):
            return

        prefix, sep, message = message.partition(' ')
        args = message.split()
        if not args:
            return
        command = args.pop(0)

        if command == 'check':
            if not args:
                self.msg(self.factory.channel, 'check what?')
                return

            target = args.pop(0)
            if not args:
                args = ['default']

            def errhandler(fail):
                self.msg(channel, 'failure: %s' % (fail.getErrorMessage(),))

            kwargs = dict(scansets=args, errhandler=errhandler)
            if isIPAddress(target):
                kwargs['ip'] = target
            else:
                kwargs['host'] = target

            try:
                result = yield self.factory.scanner.scan(**kwargs)
            except scanner.UnknownScanset, e:
                self.msg(channel, 'unknown scanset %s' % (e.args[0],))
            except DNSNameError:
                self.msg(channel, '%s did not resolve' % (target,))
            else:
                if result is None:
                    self.msg(channel, '%s is clean' % (target,))
                else:
                    self.msg(channel, '%s is bad: %s' % (target, result))
        elif command == 'stats':
            for name, semaphore in sorted(
                self.factory.scanner.pools.iteritems()):
                if semaphore.tokens:
                    self.msg(channel, '%s: %s free' % (
                            name, semaphore.tokens))
                else:
                    self.msg(channel, '%s: %s queued' % (
                            name, len(semaphore.waiting)))
            self.msg(channel, '%s checks in progress' % (
                    len(self.factory.scanner.scans),))
        elif command == 'help':
            self.msg(channel, 'commands: check stats help')


class Factory(protocol.ReconnectingClientFactory):

    protocol = Client

    # XXX did I mention this is ad-hoc and terrible yet?
    def __init__(self, nickname, channel, scanner, masks,
                 password=None, opername=None, operpass=None, away=None,
                 opermode=None, connregex=None, klinetemplate=None):
        self.bot = None
        self.nickname = nickname
        self.channel = channel
        self.password = password
        self.opername = opername
        self.operpass = operpass
        self.away = away
        self.opermode = opermode
        self.connregex = re.compile(connregex) if connregex else None
        self.scanner = scanner
        self.masks = [
            (mask, re.compile(fnmatch.translate(mask)), scansets)
            for mask, scansets in masks.iteritems()]
        self.klinetemplate = klinetemplate
