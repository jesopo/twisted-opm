# Copyright (c) 2010  Marien Zwart


"""Standard scanner plugins."""


from ..plugin import CheckerFactory


dnsbl = CheckerFactory('dnsbl', 'opm.dns.DNSBLChecker')
dns = CheckerFactory('rdns', 'opm.dns.rDNSChecker')

cert = CheckerFactory('cert', 'opm.cert.CertificateChecker')
http_headers = CheckerFactory('http-headers', 'opm.http.HeaderChecker')

http_connect = CheckerFactory('http', 'opm.proxy.HTTPConnectChecker')
http_post = CheckerFactory('http-post', 'opm.proxy.HTTPPostChecker')
http_get = CheckerFactory('http-get', 'opm.proxy.HTTPGetChecker')
wingate = CheckerFactory('wingate', 'opm.proxy.WingateChecker')
cisco = CheckerFactory('cisco', 'opm.proxy.CiscoChecker')
socks4 = CheckerFactory('socks4', 'opm.proxy.SOCKS4Checker')
socks5 = CheckerFactory('socks5', 'opm.proxy.SOCKS5Checker')
mikrotik = CheckerFactory('mikrotik', 'opm.proxy.MikrotikChecker')
