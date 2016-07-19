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


# Part 1.2: Write the SSLWrite and SSLRead I/O functions and call
# SSLSetIOFuncs to pass them to Secure Transport.
@ffi.def_extern()
def python_read_func(connection, data, data_length):
    """
    The global SSL read function.
    """
    print "Read func called"


@ffi.def_extern()
def python_write_func(connection, data, data_length):
    """
    The global SSL read function.
    """
    print "Read func called"


status = lib.SSLSetIOFuncs(
    context, lib.python_read_func, lib.python_write_func
)
assert not status

print "IO funcs set!"
