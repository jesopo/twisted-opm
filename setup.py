#!/usr/bin/env python3

from distutils.core import setup

with open("requirements.txt", "r") as requirements_file:
    install_requires = requirements_file.read().splitlines()

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
    install_requires=install_requires
)
