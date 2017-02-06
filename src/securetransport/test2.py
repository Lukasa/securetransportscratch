import h11
import socket

from securetransport.tlsapi import SecureTransportClientContext
from securetransport.tls import TLSConfiguration

conn = h11.Connection(our_role=h11.CLIENT)
ctx = SecureTransportClientContext(TLSConfiguration(ciphers=[]))
mysock = socket.create_connection(('httpbin.org', 443))
tls_sock = ctx.wrap_socket(mysock, server_hostname=b"httpbin.org")
print(tls_sock.negotiated_tls_version())
print(tls_sock.cipher())
tls_sock.do_handshake()
print(tls_sock.negotiated_tls_version())
print(tls_sock.cipher())

data = conn.send(h11.Request(method=b'GET', target=b'/get', headers=[(b'host', b'httpbin.org')]))
data += conn.send(h11.EndOfMessage())
tls_sock.sendall(data)

response_complete = False

while not response_complete:
    data = tls_sock.recv(8192)
    print(data.decode('utf-8'),)
    conn.receive_data(data)

    while True:
        evt = conn.next_event()
        if evt is h11.NEED_DATA:
            break

        if isinstance(evt, h11.EndOfMessage):
            response_complete = True

tls_sock.close()
