#!/usr/bin/env python3

from distutils.core import setup

setup(
    name="twisted-opm",
    version="0.1",
    author="Marien Zwart, jesopo",
    author_email="txopm@lolnerd.net",
    url="https://github.com/jesopo/twisted-opm",
    description="Twisted-based BOPM-like open proxy scanner.",
    license="MIT",
    packages=["opm", "opm/plugins", "twisted/plugins"],
    python_requires=">=3.5",
    install_requires=[
        'cryptography>=3.1',
        'ircchallenge==0.1.1',
        'pyyaml      >=5.3.1',
        'Twisted     >=20.3.0',
        'pyOpenSSL   >=20.0.1',
    ]
)
