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

    In the future we should check with curl's implementation of this to do
    better.
    """
    print "Read func called with data_length %d" % data_length[0]
    socket = ffi.from_handle(connection)
    data_to_go = data_length[0]
    data_read = 0
    data_buffer = ffi.buffer(data, data_length[0])

    while data_to_go > 0:
        data_chunk = socket.recv(data_to_go)
        data_buffer[data_read:data_read + len(data_chunk)] = data_chunk
        data_to_go -= len(data_chunk)
        data_read += len(data_chunk)

    return 0


@ffi.def_extern()
def python_write_func(connection, data, data_length):
    """
    The global SSL read function.
    """
    print "Write func called"
    socket = ffi.from_handle(connection)
    data = ffi.buffer(data, data_length[0])
    socket.sendall(data)
    return 0


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


# Part 1.5: Call SSLSetCertificate to specify the certificate to be used in
# authentication (required for server side, optional for client).
# We're skipping this for now.


# Part 2: Starting a session
# Part 2.1: Call SSLHandshake to perform the SSL handshake and establish a
# secure session.
s.connect((server_name, 443))
status = lib.SSLHandshake(context)
assert not status
print "Handshake complete!"
