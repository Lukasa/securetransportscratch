# -*- coding: utf-8 -*-
"""
Example implementation of the TLS abstract API using SecureTransport.

As with so much of this, implementing the side functionality is best done by
following the old networking adage: "when in doubt, do what curl does".
For future reference then:
https://github.com/curl/curl/blob/master/lib/vtls/darwinssl.c
"""
from typing import Optional, Any, Union

import socket

from .tls import (
    ClientContext, TLSWrappedSocket, TLSWrappedBuffer, Backend, TrustStore,
    TLSConfiguration, CipherSuite, NextProtocol, TLSVersion, WantWriteError,
    WantReadError, TLSError
)
from .low_level import (
    SSLSessionContext, SSLProtocolSide, SSLConnectionType, SSLSessionState,
    SecureTransportError, WouldBlockError, SSLErrors
)


class SecureTransportClientContext(object):
    """
    A ClientContext for SecureTransport.
    """
    def __init__(self, configuration: TLSConfiguration):
        """
        Create a new client context from a given TLSConfiguration.
        """
        self.__configuration = configuration

    @property
    def configuration(self) -> TLSConfiguration:
        return self.__configuration

    def wrap_socket(self, socket: socket.socket,
                          server_hostname: Optional[str],
                          auto_handshake: bool = True) -> TLSWrappedSocket:
        buffer = _SecureTransportBuffer(server_hostname, self)
        return WrappedSocket(socket, buffer)

    def wrap_buffers(self, incoming: Any, outgoing: Any,
                           server_hostname: Optional[str]) -> TLSWrappedBuffer:
        pass


class WrappedSocket(TLSWrappedSocket):
    """
    A wrapped socket implementation. This uses the _SecureTransportBuffer to
    implement everything else.
    """
    def __init__(self, socket, buffer):
        self.__dict__['_socket'] = socket
        self.__dict__['_buffer'] = buffer

    def do_handshake(self) -> None:
        # This method needs to work with sockets in three modes: non-blocking,
        # blocking, and timeout. For non-blocking and timeout sockets the rule
        # is: read only once. If those attempts to read raise, they raise.

        # TODO: refactor all of this nonsense to use selectors.
        blocking = self._socket.gettimeout() is None
        done_io = False

        while True:
            try:
                self._buffer.do_handshake()
            except WantReadError:
                # If we're in non-blocking mode, we want to raise an error
                # here.
                if not blocking and done_io:
                    raise

                data = self._socket.recv(8192)
                if not data:
                    raise TLSError("Unexpected EOF during handshake")
                self._buffer.receive_bytes_from_network(data)
                done_io = True
            except WantWriteError:
                # If we're in non-blocking mode, we want to raise an error
                # here.
                if not blocking and done_io:
                    raise

                some_data = self._buffer.peek_bytes(8192)
                sent = self._socket.send(some_data)
                self._buffer.consume_bytes(sent)
            else:
                # Handshake complete!
               break

    def cipher(self) -> Optional[CipherSuite]:
        return self._buffer.cipher()

    def negotiated_protocol(self) -> Optional[Union[NextProtocol, bytes]]:
        return self._buffer.negotiated_protocol()

    @property
    def context(self) -> SecureTransportClientContext:
        return self._buffer.context

    @property
    def negotiated_tls_version(self) -> Optional[TLSVersion]:
        return self._buffer.negotiated_tls_version

    def unwrap(self) -> socket.socket:
        self._buffer.shutdown()

        # TODO: So, does unwrap make any sense here? How do we make sure we
        # read up to close_notify, but no further?
        while True:
            some_data = self._buffer.peek_bytes(8192)
            if not some_data:
                break
            sent = self._socket.send(some_data)
            self._buffer.consume_bytes(sent)

        return self._socket

    def close(self):
        # TODO: we need to do better here with CLOSE_NOTIFY. In particular, we
        # need a way to do a graceful connection shutdown that produces data
        # until the remote party has done CLOSE_NOTIFY.
        self.unwrap()
        self._socket.close()

    def recv(self, bufsize, flags=0):
        # Do we need to loop here to prevent WantReadError being raised for
        # blocking sockets?
        try:
            return self._buffer.read(bufsize)
        except WantReadError:
            data = self._socket.recv(8192, flags)
            if not data:
                return b''
            self._buffer.receive_bytes_from_network(data)
            return self._buffer.read(bufsize)

    def recv_into(self, buffer, nbytes=None, flags=0):
        read_size = nbytes or len(buffer)
        data = self.read(read_size, flags)
        buffer[:len(data)] = data
        return len(data)

    def send(self, data, flags=0):
        # TODO: Timeouts here need to be turned into deadlines.
        try:
            self._buffer.write(data)
        except WantWriteError:
            # TODO: Ok, so this is a fun problem. Let's talk about it.
            #
            # If we make the rule that the socket will always drain the send
            # buffer when sending data (a good plan, and one that matches the
            # behaviour of the legacy ``ssl`` module), then the only way
            # WantWriteError can occur is if the amount of data to be written
            # is larger than the write buffer in the buffer object.
            # Now OpenSSL tolerates this by basically saying that if this
            # happens, you need to drain the write buffer, and then to call
            # "SSL_write" again with the exact same buffer, and it'll just
            # continue from where it was.
            #
            # This is a pretty stupid behaviour, but it's do-able. The bigger
            # problem is that, while we could in principle change it (e.g. by
            # having WantWriteError indicate how many bytes were consumed),
            # making that change will require that OpenSSL implementations
            # bend over backwards to work around their requirement to reuse the
            # same buffer.
            #
            # All of this is wholly gross, and I haven't really decided how I
            # want to proceed with it, but we do need to decide how we want to
            # handle it before we can move forward.

            # TODO: Another relevant reference for us is this comment from the
            # curl codebase: https://github.com/curl/curl/blob/807698db025f489dd7894f1195e4983be632bee2/lib/vtls/darwinssl.c#L2477-L2489
            pass

        sent = 0
        while True:
            some_data = self._buffer.peek_bytes(8192)
            if not some_data:
                break
            sent += self._socket.send(some_data, flags)
            self._buffer.consume_bytes(sent)
        return sent

    def sendall(self, bytes, flags=0):
        send_buffer = memoryview(bytes)
        while send_buffer:
            sent = self.send(send_buffer, flags)
            send_buffer = send_buffer[sent:]

        return

    def makefile(self, mode='r', buffering=None, *, encoding=None, errors=None, newline=None):
        pass

    def __getattr__(self, attribute):
        return getattr(self._socket, attribute)

    def __setattr__(self, attribute, value):
        return setattr(self._socket, attribute, value)


class _SecureTransportBuffer(TLSWrappedBuffer):
    def __init__(self, server_hostname, context):
        self._original_context = context

        self._st_context = SSLSessionContext(
            SSLProtocolSide.Client, SSLConnectionType.StreamType
        )
        self._st_context.set_io_funcs(self._read_func, self._write_func)
        if server_hostname is not None:
            self._st_context.set_peer_domain_name(server_hostname)

        self._receive_buffer = bytearray()
        self._send_buffer = bytearray()

    def _io_error(self):
        """
        Raises the appropriate I/O error if we got a WouldBlockError.
        """
        # The way SecureTransport works here is a bit tricky. Ideally we'd
        # track which was the last I/O operation that returned "short", but
        # that doesn't actually work: SecureTransport will issue a bunch of
        # somewhat unexpected reads after it has issued a write. In practice,
        # almost all errSSLWouldBlock errors come from the read callback, not
        # the write callback, even though what ST actually wants is for the
        # user to WRITE THAT DAMN DATA so that the server will respond. That
        # means that if we just cared what the last "short" operation was we'd
        # get a bunch of WantReadErrors that are more philosophical than
        # helpful: yes, we do want to read, but we want to read something that
        # won't arrive until we write. That would make us *technically* correct
        # (the best kind of correct), but not very helpful.
        #
        # So instead what we do is check the state of the buffers. If there is
        # data in the send buffer, we assume that we need to drain that buffer
        # first before any further operations will work, either for reads or
        # for writes.
        if self._send_buffer:
            return WantWriteError("Must write data")

        return WantReadError("Must read data")

    def _read_func(self, _, to_read):
        # We're doing some unnecessary copying here, but that's ok for
        # demo purposes.
        rc = 0
        output_data = self._receive_buffer[:to_read]
        del self._receive_buffer[:to_read]

        if len(output_data) < to_read:
            rc = SSLErrors.errSSLWouldBlock

        return rc, output_data

    def _write_func(self, _, data):
        self._send_buffer += data
        return 0, len(data)

    def read(self, amt: Optional[int] = None) -> bytes:
        assert amt is not None
        try:
           return self._st_context.read(amt)
        except WouldBlockError:
            raise self._io_error() from None

    def readinto(self, buffer: Any, amt: Optional[int] = None) -> int:
        if amt is None or amt > len(buffer):
            amt = len(buffer)

        data = self.read(amt)
        buffer[:len(data)] = data
        return len(data)

    def write(self, buf: Any) -> int:
        try:
            return self._st_context.write(buf)
        except WouldBlockError:
            raise self._io_error() from None

    def do_handshake(self) -> None:
        try:
            self._st_context.handshake()
        except WouldBlockError:
            raise self._io_error() from None

    def cipher(self) -> Optional[CipherSuite]:
        pass

    def negotiated_protocol(self) -> Optional[Union[NextProtocol, bytes]]:
        pass

    @property
    def context(self) -> SecureTransportClientContext:
        return self._original_context

    def negotiated_tls_version(self) -> Optional[TLSVersion]:
        pass

    def shutdown(self) -> None:
        # A note: SSLClose will write the close_notify, but won't wait to read
        # it. That means we can't really look for a close_notify. Awkward.
        #
        # I'm not sure how best to handle this. Do we just read to EOF? How?
        try:
            self._st_context.close()
        except WouldBlockError:
            # TODO: do we just swallow this instead?
            raise self._io_error() from None

    def receive_bytes_from_network(self, bytes):
        self._receive_buffer += bytes

    def peek_bytes(self, len):
        return self._send_buffer[:len]

    def consume_bytes(self, len):
        del self._send_buffer[:len]


class SecureTransportTrustStore(TrustStore):
    @classmethod
    def system(cls):
        """
        Returns a TrustStore object that represents the system trust
        database.
        """
        # We just use a sentinel object here.
        return __SystemTrustStore

    @classmethod
    def from_pem_file(cls, path):
        raise NotImplementedError(
            "SecureTransport does not support PEM bundles as trust stores"
        )


__SystemTrustStore = SecureTransportTrustStore()


SecureTransportBackend = Backend(
    client_context=SecureTransportClientContext, server_context=None,
    certificate=None, private_key=None, trust_store=SecureTransportTrustStore
)
