# -*- coding: utf-8 -*-
"""
Test code for SecureTransport.
"""
import socket

from securetransport.low_level import (
    SSLSessionContext, SSLProtocolSide, SSLConnectionType
)

# Part 1: Preparing For A Session
# Part 1.1: Call SSLCreateContext to create a new SSL session context.
context = SSLSessionContext(
    SSLProtocolSide.Client, SSLConnectionType.StreamType
)
print "Created context: %s" % context


# Part 1.2: Write the SSLWrite and SSLRead I/O functions and call
# SSLSetIOFuncs to pass them to Secure Transport.
def read_func(s, data_to_go):
    """
    The SSL read function.

    In the future we should check with curl's implementation of this to do
    better.
    """
    data_read = 0
    data = []

    while data_to_go > 0:
        data_chunk = s.recv(data_to_go)
        data_read += len(data_chunk)
        data_to_go -= len(data_chunk)
        data.append(data_chunk)

    return 0, b''.join(data)


def write_func(s, data):
    """
    The SSL write function.
    """
    s.sendall(data)
    return 0, len(data)


context.set_io_funcs(read_func, write_func)
print "IO funcs set!"


# Part 1.3: Establish a connection using CFNetwork, BSD Sockets, or Open
# Transport. Then call SSLSetConnection to specify the connection to which the
# SSL session context applies.
s = socket.socket()
context.set_connection(s)
print "Connection set to %s" % s


# Part 1.4: Call SSLSetPeerDomainName to specify the fully-qualified domain
# name of the peer to which you want to connect (optional but highly
# recommended).
server_name = b"http2bin.org"
context.set_peer_domain_name(server_name)
print "Peer domain name set to %s" % server_name

# TEST
@ffi.def_extern()
def python_alpn_func(context, info, alpn_data, size):
    real_data = ffi.buffer(alpn_data, size)[:]
    print "Got ALPN data %s" % real_data


alpn_data = b"\x08http/1.1"
status = lib.SSLSetALPNData(context, alpn_data, len(alpn_data))
assert not status, "status %s" % status
status = lib.SSLSetALPNFunc(context, lib.python_alpn_func, ffi.NULL)
print "Set ALPN"


# Part 1.5: Call SSLSetCertificate to specify the certificate to be used in
# authentication (required for server side, optional for client).
# We're skipping this for now.


# Part 2: Starting a session
# Part 2.1: Call SSLHandshake to perform the SSL handshake and establish a
# secure session.
s.connect((server_name, 443))
context.handshake()
print "Handshake complete!"

# Part 3: Maintaining the Session
# In this case, let's attempt to make a basic HTTP request!
request = (
    b'GET /get HTTP/1.1\r\n'
    b'Host: http2bin.org\r\n'
    b'Accept: */*\r\n'
    b'Accept-Encoding: identity\r\n'
    b'\r\n'
)
bytes_written = context.write(request)
assert bytes_written == len(request)

response = b''
while True:
    response += context.read(65535)
    if response.endswith(b'"url": "https://http2bin.org/get"\n}\n'):
        break

print response


# Part 4: Ending a session
# Part 4.1: Call SSLClose to close the secure session.
context.close()

# Part 4.2: Close the connection and dispose of the connection reference
# (SSLConnectionRef).
s.shutdown(socket.SHUT_RDWR)  # This is normally unnecessary, but let's block.
s.close()

# Part 4.3: If you created the context by calling SSLCreateContext, release the
# SSL session context by calling CFRelease.
del context

# Part 4.4: If you have called SSLGetPeerCertificates to obtain any
# certificates, call CFRelease to release the certificate reference objects.
# Not relevant to us.
print "Disposed successfully!"
