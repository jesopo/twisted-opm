

from twisted.application.service import ServiceMaker


OPM = ServiceMaker(
    'OPM',
    'opm.conf',
    'Open Proxy Monitor',
    'opm')
