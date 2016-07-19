#!/usr/bin/env python
from setuptools import setup, find_packages

setup(
    name="securetransport",
    version="0.0.1",

    description="Python binding to SecureTransport",
    license="MIT",

    author="Cory Benfield",
    author_email="cory@lukasa.co.uk",

    setup_requires=[
        "cffi>=1.0.0",
    ],
    install_requires=[
        "cffi>=1.0.0",
    ],

    cffi_modules=["src/securetransport/build.py:ffibuilder"],

    packages=find_packages('src'),
    package_dir={'': 'src'},

    zip_safe=False,
)