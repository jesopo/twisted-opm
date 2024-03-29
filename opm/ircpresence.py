# Copyright (c) 2010  Marien Zwart


"""IRC client listening for connections and commands.

This is all pretty ad-hoc and terrible.
"""


from __future__ import absolute_import, with_statement, division

import random, re
import fnmatch

from twisted.python import log
from twisted.internet import protocol, defer
from twisted.words.protocols import irc
from twisted.names.error import DNSNameError

try:
    from ircchallenge import Challenge
    has_challenge = True
except ModuleNotFoundError:
    has_challenge = False

from . import scanner
from . import cache

class Client(irc.IRCClient):

    clock = None
    challenge = None

    messagePenalty = 2 # seconds
    messageBurst = 10 # seconds

    # Defaults to None which kind of sucks.
    realname = 'txOPM'

    def connectionMade(self):
        self.nickname = self.factory.nickname
        self.username = self.factory.username
        self.password = self.factory.password
        if self.clock is None: # pragma: no cover
            from twisted.internet import reactor
            self.clock = reactor
        self.messageTimer = 0

        self.ip_cache     = cache.Cache(self.factory.cache_size)
        self.immune_cache = cache.Cache(1<<8) # larger than we should hit

        irc.IRCClient.connectionMade(self)

    def sendLine(self, line):
        # Overridden to do rfc1459-style rate limiting.
        if self.factory.verbose:
            log.msg('IRC OUT %r' % (line,))
        self._queue.append(line)
        if not self._queueEmptying:
            self._sendLines()

    def dataReceived(self, data):
        if isinstance(data, bytes):
            try:
                data = data.decode("utf8")
            except UnicodeDecodeError:
                data = data.decode("latin-1")
        super().dataReceived(data)

    def lineReceived(self, line):
        if self.factory.verbose:
            log.msg('IRC IN  %r' % (line,))
        irc.IRCClient.lineReceived(self, line)

    def _sendLines(self):
        now = self.clock.seconds()
        if self.messageTimer < now:
            self.messageTimer = now

        while self._queue and self.messageTimer <= now + self.messageBurst:
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
        for target, msg in self.factory.onconnectmsgs:
            self.msg(target, msg)

        if self.factory.opername:
            if self.factory.operkey:
                if has_challenge:
                    self.challenge = Challenge(keyfile=self.factory.operkey,
                        password=self.factory.operpass)
                    self.sendLine(f'CHALLENGE {self.factory.opername}')
                else:
                    log.err("challenge configured but support not available")

            elif self.factory.operpass:
                self.oper(self.factory.opername, self.factory.operpass)

        if self.factory.away:
            self.away(self.factory.away)
        self.join(self.factory.channel)
        self.factory.bot = self
        self.factory.resetDelay()

    def irc_740(self, prefix, params):
        # RPL_RSACHALLENGE2
        if self.challenge is not None:
            self.challenge.push(params[1])
    def irc_741(self, prefix, params):
        # RPL_ENDOFRSACHALLENGE2
        if self.challenge is not None:
            retort = self.challenge.finalise()
            self.challenge = None
            self.sendLine(f'CHALLENGE +{retort}')

    def irc_RPL_YOUREOPER(self, prefix, params):
        # nick, message = params
        if self.factory.opermode:
            # The IRCClient "mode" method sucks, bypass it
            self.sendLine(
                'MODE %s %s' % (self.nickname, self.factory.opermode))

        if self.factory.flood_exempt:
            self.messagePenalty = 0

    def connectionLost(self, reason):
        self.factory.bot = None
        if self._queueEmptying is not None:
            self._queueEmptying.cancel()
            self._queueEmptying = None
        return irc.IRCClient.connectionLost(self, reason)

    @defer.inlineCallbacks
    def noticed(self, user, channel, message):
        # We only care about notices from the server, not from users.
        # Users have a hostmask as "user", servers do not.
        if '!' in user:
            return

        if self.factory.connregex is None:
            return

        match = self.factory.connregex.search(message)
        if match is None:
            return

        d = match.groupdict()

        nick = d['nick']
        user = d['user']
        ip =   d['ip']
        host = d.get("host", ip)

        if ip == '0':
            # cliconn for a remote iline spoofed user
            return
        ip_hostmask = f'{nick}!{user}@{ip}'
        ux_hostmask = f'{nick}!{user}@{host}'

        scansets = set()
        for mask, pattern, sets in self.factory.masks:
            if pattern.match(ip_hostmask) is not None:
                scansets.update(sets)

        if ip in self.immune_cache:
            log.msg(f'Immunity given to {ux_hostmask}|{ip}')
            result = None
        elif ip in self.ip_cache:
            result = self.ip_cache.get(ip)
            log.msg(f'Cache hit for {ux_hostmask}|{ip}: {result}')
        else:
            log.msg(f'Scanning {ux_hostmask}|{ip} on scanners {" ".join(scansets)}')
            result = yield self.factory.scanner.scan(ip, scansets)
            self.ip_cache.set(ip, result, self.factory.cache_time)

        if result is not None:
            scanset, result = result
            formats = {
                'IP': ip,
                'NICK': nick,
                'USER': user,
                'HOST': host,
                'MASK': ux_hostmask,
                'CHAN': self.factory.channel,
                'REASON': result,
                'RANDOM': random.randint(160, 320)
            }

            for action in scanset.actions:
                self.sendLine(action.format(**formats))

            log.msg(f'KILL {ux_hostmask} for {result}')
        else:
            log.msg(f'GOOD {hostmask}')

    def privmsg(self, user, channel, message):
        # We use access to our channel as access control.
        # Private messages are rejected.
        if channel != self.factory.channel:
            return

        prefixes = [f"{self.nickname}{p}" for p in ("", ':', ',', ';')]
        prefixes.append("!topm")
        prefix, sep, message = message.partition(' ')
        if not prefix in prefixes:
            return

        args = message.split()
        if not args:
            return
        command = args.pop(0)

        handler = getattr(self, 'cmd_' + command, None)
        if handler is not None:
            return handler(channel, args)

    @defer.inlineCallbacks
    def cmd_check(self, channel, args):
        if not args:
            self.msg(self.factory.channel, 'check what?')
            return

        target = args.pop(0)
        if not args:
            args = ['default']

        def errhandler(fail):
            self.msg(channel, 'failure: %s' % (fail.getErrorMessage(),))

        try:
            result = yield self.factory.scanner.scan(
                target, scanset_names=args, errhandler=errhandler
            )
        except scanner.UnknownScanset as e:
            self.msg(channel, 'unknown scanset %s' % (e.args[0],))
        except DNSNameError:
            self.msg(channel, '%s did not resolve' % (target,))
        else:
            if result is None:
                self.msg(channel, '%s is clean' % (target,))
            else:
                scanset, output = result
                self.msg(channel, '%s is bad: %s' % (target, output))

    def cmd_stats(self, channel, args):
        for name, semaphore in sorted(
            self.factory.scanner.pools.items()):
            if semaphore.tokens:
                self.msg(channel, '%s: %s free' % (
                        name, semaphore.tokens))
            else:
                self.msg(channel, '%s: %s queued' % (
                        name, len(semaphore.waiting)))
        self.msg(channel, '%s checks in progress' % (
                len(self.factory.scanner.scans),))

    def cmd_help(self, channel, args):
        self.msg(channel, 'commands: check stats help')

    def cmd_decache(self, channel, args):
        if args:
            ip = args[0]
            if ip in self.ip_cache:
                del self.ip_cache[ip]
                self.msg(channel, 'removed %s from cache' % (ip,))
            else:
                self.msg(channel, '%s not in cache' % (ip,))
        else:
            if self.ip_cache:
                self.ip_cache.clear()
                self.msg(channel, 'cleared cache')
            else:
                self.msg(channel, 'cache is empty')

    def cmd_immune(self, channel, args):
        if len(args) > 1 and args[1].isdigit():
            ip, seconds, *_ = args
            self.immune_cache.set(ip, True, int(seconds))
            self.msg(channel, f'{ip} immune for {seconds} seconds')
        else:
            self.msg(channel, 'invalid arguments (immune <ip> <seconds>)')

class Factory(protocol.ReconnectingClientFactory):

    protocol = Client

    # XXX did I mention this is ad-hoc and terrible yet?
    def __init__(self, nickname, channel, scanner, masks,
                 password=None, opername=None, operpass=None, operkey=None,
                 away=None, opermode=None, connregex=None, actions=None,
                 onconnectmsgs=(), verbose=False, flood_exempt=False,
                 username=None, cache_time=None, cache_size=None):
        self.bot = None
        self.nickname = nickname
        self.username = username
        self.channel = channel
        self.password = password
        self.opername = opername
        self.operpass = operpass
        self.operkey  = operkey
        self.away = away
        self.opermode = opermode
        self.connregex = re.compile(connregex) if connregex else None
        self.scanner = scanner
        self.masks = [
            (mask, re.compile(fnmatch.translate(mask)), scansets)
            for mask, scansets in masks.items()]
        self.actions = actions
        self.onconnectmsgs = onconnectmsgs
        self.verbose = verbose
        self.flood_exempt = flood_exempt
        self.cache_time = cache_time
        self.cache_size = cache_size
