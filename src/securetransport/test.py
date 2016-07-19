# -*- coding: utf-8 -*-
"""
Test code for SecureTransport.
"""
import socket

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


# Part 1.3: Establish a connection using CFNetwork, BSD Sockets, or Open
# Transport. Then call SSLSetConnection to specify the connection to which the
# SSL session context applies.
s = socket.socket()
socket_handle = ffi.new_handle(s)
status = lib.SSLSetConnection(context, socket_handle)
assert not status
print "Connection set to %s" % socket_handle


# Part 1.4: Call SSLSetPeerDomainName to specify the fully-qualified domain
# name of the peer to which you want to connect (optional but highly
# recommended).
server_name = b"http2bin.org"
server_name_len = len(server_name)
status = lib.SSLSetPeerDomainName(context, server_name, server_name_len)
assert not status
print "Peer domain name set to %s" % server_name
