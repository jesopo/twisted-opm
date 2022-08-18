# Copyright (c) 2010  Marien Zwart


"""Configuration and service creation."""


from __future__ import absolute_import, with_statement, division

try:
    import resource
    resource # shut up pyflakes
except ImportError: # pragma: no cover
    resource = None

from twisted.python import usage
from twisted.application import service, internet
from twisted.internet import ssl

import base64, yaml

from . import ircpresence, scanner, plugin

def badbinary_constructor(loader, node):
    value = loader.construct_scalar(node)
    return base64.b64decode(value)
yaml.SafeLoader.add_constructor("!binary", badbinary_constructor)

# XXX string/unicode handling in this code is sloppy.
# Should work as long as the config file is all ascii.

# XXX this is not written with config re-hashing in mind.


class Options(usage.Options):

    synopsis = '[--force-select] <conffile>'

    optFlags = [
        ('force-select', None, 'Accept the selectreactor.'),
        ('keep-resolver', None, 'Keep the default resolver.'),
        ('force-limits', None, 'Bypass resource limit checks.'),
        ('irc-log', None, 'Log all irc traffic'),
        ]

    def parseArgs(self, conffile):
        try:
            with open(conffile, 'rb') as f:
                self['conf'] = yaml.safe_load(f)
        except EnvironmentError as e:
            raise usage.error('Cannot open %s: %s' % (conffile, e))

    def postOptions(self):
        if resource is not None and not self['force-limits']:
            total_pool_size = sum(self['conf'].get('pools', {}).values())
            soft_limit, hard_limit = resource.getrlimit(
                resource.RLIMIT_NOFILE)
            if soft_limit < total_pool_size:
                raise usage.error(
                    'fd limit %d < %d, use --force-limits to override' % (
                        soft_limit, total_pool_size))


def makeService(options):
    from twisted.names.client import getResolver
    resolver = getResolver()
    # HACK: I want a better resolver than the threaded one, and lack a
    # non-terrible place to install it.
    from twisted.internet import reactor
    if not options['keep-resolver']: # pragma: no cover
        reactor.installResolver(resolver)

    # HACK: warn about suboptimal reactor usage
    if not options['force-select']: # pragma: no cover
        from twisted.internet import selectreactor
        if isinstance(reactor, selectreactor.SelectReactor):
            print('The select reactor is probably a bad idea.')
            print('Please use a reactor with better support for lots of fds.')
            print('(-r epoll for example)')
            print('You can bypass this check using --force-select')
            print()
            raise ValueError('unfortunate reactor choice')

    m = service.MultiService()

    checkerFactories = plugin.getCheckerFactories()

    scansets = {}
    for name, d in options['conf']['scansets'].items():
        scans = []
        for args in d['protocols']:
            poolname = args.pop(0)
            checkername = args.pop(0)
            checker = checkerFactories[checkername](*args)
            scans.append((poolname, checker.check))

        actions = d.get('actions', [])
        scansets[name] = scanner.ScanSet(d['timeout'], scans, actions)

    # XXXX the target_blah passing here is horrible, but I intend to
    # make this less global in the future anyway, so laaaaaaaaater
    env = {}
    for k in ['target_ip', 'target_port', 'target_url', 'target_strings',
              'max_bytes', 'bind_address']:
        env[k] = options['conf'].get(k)

    theScanner = scanner.Scanner(
        reactor, resolver, options['conf']['pools'], scansets, env)

    for name, net in options['conf'].get('irc', {}).items():
        # XXX terrible, see also similar complaints in ircpresence.
        # Split this up later.
        factory = ircpresence.Factory(
            net['nick'], net['channel'],
            password=net.get('pass'),
            opername=net.get('opername', net['nick']),
            operpass=net.get('operpass'),
            operkey =net.get('operkey'),
            opermode=net.get('opermode'),
            away=net.get('away'),
            connregex=net.get('connregex'),
            scanner=theScanner,
            masks=options['conf'].get('masks', {}),
            actions=net.get('actions'),
            onconnectmsgs=net.get('onconnectmsgs', ()),
            verbose=options['irc-log'],
            flood_exempt=net.get('flood_exempt', False),
            username=net.get('username'),
            cache_time=net.get("scan-cache-time", 120),
            cache_size=net.get("scan-cache-size", 1_000_000)
            )
        if net.get('ssl', False):
            # XXX allow config to define a hostname just for validation purposes
            ctx = ssl.optionsForClientTLS(net['host'])
            serv = internet.SSLClient(net['host'], net['port'], factory, ctx)
        else:
            serv = internet.TCPClient(net['host'], net['port'], factory)
        serv.setName(name)
        serv.setServiceParent(m)

    return m
