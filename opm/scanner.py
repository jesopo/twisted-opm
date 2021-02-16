# Copyright (c) 2010  Marien Zwart


"""Scanner manager."""


from __future__ import absolute_import, with_statement, division

from twisted.python import log
from twisted.internet import defer
from twisted.names.error import DNSNameError

from . import util, default_dns_pool_size


# Thoughts:
#
# It is probably worthwhile to not kick off parallel scans of the same
# ip, to avoid idiocy if someone connects a ton of clients from the
# same host (DoS-ing the scanner, disturbing scans of other hosts). We
# might even want to not scan again if someone connects immediately
# after a scan. But (as bopm.conf.sample points out) caching negative
# results is dangerous, because someone can disable their proxy,
# connect, and immediately enable it again.
#
# Currently we only cache if a scan is currently in progress, assuming
# our timeout settings keep us in check.
#
# Note the numbers for FD usage can get a little high if we're naive:
# with a timeout of 30 seconds, 300 scans to run (in parallel), and 1
# connection per second on average, we'd need about 9000 of them.
#
# To get new hosts scanned quickly I think having multiple pools of
# FDs makes sense. If the scanner is loaded it will take a while for
# all scans on each new connection to finish, but the common ones can
# start quickly.


class UnknownScanset(KeyError):
    pass


class Scan(object):

    """Scan for any single target.

    Initially started and finished are both false.

    After all initial checks have been added "started" call start().

    Checks can be added at any time, but only actually run if finished
    is not set yet.
    """

    def __init__(self, clock, ip, errhandler=None):
        self.clock = clock
        self.ip = ip
        self.started = False
        self.finished = False
        self.checks = set()
        self.running = {}
        self.result = None
        self.waiting = []
        self.errhandlers = [log.err]
        if errhandler is not None:
            self.errhandlers.append(errhandler)

    def getResult(self):
        if self.result is not None:
            # We already found something. Return it immediately.
            return defer.succeed(self.result)

        if self.finished:
            # We already ran all our checks, and are clean.
            return defer.succeed(None)

        # Wait for our checks to finish.
        d = defer.Deferred()
        self.waiting.append(d)
        return d

    def _setResult(self, result):
        self.result = result
        self.finished = True
        waiting = self.waiting
        self.waiting = None
        for d in waiting:
            d.callback(result)

    def addCheck(self, check, pool, scanset, *args):
        if self.finished:
            return

        if (check, scanset.timeout) in self.checks:
            return

        self.checks.add((check, scanset.timeout))

        d = pool.run(check, self, *args)
        self.running[(check, scanset.timeout)] = d

        @d.addBoth
        def killRunning(result):
            del self.running[(check, scanset.timeout)]
            return result

        def checked(result):
            if result is not None:
                # We found something:
                self._setResult((scanset, result))

                # Stop all other checks:
                # (list(...) because it'll change size during iteration)
                running = list(self.running.values())
                for d in running:
                    d.cancel()
                assert not self.running

        def failed(fail):
            fail.trap(defer.CancelledError)

        d.addCallbacks(checked, failed)
        @d.addErrback
        def report(fail):
            for errhandler in self.errhandlers:
                errhandler(fail)

        @d.addBoth
        def maybeFinished(ignored):
            if self.started and not self.running and not self.result:
                # We were the last pending check to finish. We're clean.
                self._setResult(None)
            return ignored

        # TODO: might be worth it performance-wise to batch our timeouts.

        # We do not bother cancelling these timeouts: cancelling an
        # already cancelled deferred is a noop.
        self.clock.callLater(scanset.timeout, d.cancel)

    def start(self):
        self.started = True
        if not self.running and not self.finished:
            # All our checks finished synchronously. We're done.
            self._setResult(None)

class ScanSet(object):
    def __init__(self, timeout, scans, actions):
        self.timeout = timeout
        self.scans   = scans
        self.actions = actions

class ScanEnvironment(object):

    """Object passed to our checkers holding global resources.

    There is one of these for each Scanner. They are separate objects
    to keep the Scanner code more obvious and stop checkers from doing
    naughty things to the Scanner.
    """

    def __init__(self, reactor, resolver):
        self.reactor = reactor
        self.resolver = resolver


class Scanner(object):

    def __init__(self, reactor, resolver, pools, scansets, env):
        """"Initialize.

        pools is a mapping pool name -> size
        scansets is a mapping scanset name -> ScanSet object
        """
        self.reactor = reactor
        self.resolver = resolver
        self.env = ScanEnvironment(reactor, resolver)
        # XXX quick hack, refactor later.
        for k, v in env.items():
            setattr(self.env, k, v)
        self.scans = {}
        self.pools = dict((name, defer.DeferredSemaphore(n))
                          for name, n in pools.items())
        self.dnspool = self.pools.get(
            'dns', defer.DeferredSemaphore(default_dns_pool_size))
        self.scansets = scansets

    @defer.inlineCallbacks
    def scan(self, ip, scanset_names=[], errhandler=None):
        """Get a Scan object for an ip."""

        scans = set()
        for scanset_name in scanset_names:
            try:
                scans.add(self.scansets[scanset_name])
            except KeyError:
                raise UnknownScanset(scanset_name)

        if not scans:
            defer.returnValue(None)

        if ip not in self.scans:
            log.msg('starting scan for %s' % (ip,))
            self.scans[ip] = scan = Scan(self.reactor, ip,
                                         errhandler=errhandler)
            d = scan.getResult()
            @d.addBoth
            def scanFinished(result):
                del self.scans[ip]
                return result
            d.addErrback(log.err)
        else:
            # Reuse the existing scanner (should be infrequent)
            log.msg('scan for %s already in progress, adding to it' % (ip,))
            scan = self.scans[ip]
            if errhandler is not None:
                scan.errhandlers.append(errhandler)

        for scanset in scans:
            for poolname, check in scanset.scans:
                scan.addCheck(check, self.pools[poolname], scanset, self.env)

        scan.start()

        result = yield scan.getResult()
        defer.returnValue(result)
