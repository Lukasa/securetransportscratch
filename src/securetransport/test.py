# -*- coding: utf-8 -*-
"""
Test code for SecureTransport.
"""

from _securetransport import ffi, lib

# Part 1: Preparing For A Session
# Part 1.1: Call SSLCreateContext to create a new SSL session context.
context = lib.SSLCreateContext(
    ffi.NULL, lib.kSSLClientSide, lib.kSSLStreamType
)
print "Created context: %s" % context
