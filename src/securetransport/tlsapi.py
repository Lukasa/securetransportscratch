# -*- coding: utf-8 -*-
"""
Example implementation of the TLS abstract API using SecureTransport.

As with so much of this, implementing the side functionality is best done by
following the old networking adage: "when in doubt, do what curl does".
For future reference then:
https://github.com/curl/curl/blob/master/lib/vtls/darwinssl.c
"""
from typing import Optional, Any, Union

import selectors
import socket
import time

from contextlib import contextmanager

from .tls import (
    ClientContext, TLSWrappedSocket, TLSWrappedBuffer, Backend, TrustStore,
    TLSConfiguration, CipherSuite, NextProtocol, TLSVersion, WantWriteError,
    WantReadError, TLSError
)
from .low_level import (
    SSLSessionContext, SSLProtocolSide, SSLConnectionType, SSLSessionState,
    SecureTransportError, WouldBlockError, SSLErrors, SSLProtocol,
    SSLSessionOption
)


class _Timer:
    def __enter__(self):
        self.start = time.monotonic()

    def __exit__(self, *args):
        self.end = time.monotonic()
        self.duration = self.end - self.start


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

    def wrap_buffers(self, server_hostname: Optional[str]) -> TLSWrappedBuffer:
        return _SecureTransportBuffer(server_hostname, self)


class WrappedSocket(TLSWrappedSocket):
    """
    A wrapped socket implementation. This uses the _SecureTransportBuffer to
    implement everything else.
    """
    def __init__(self, socket, buffer):
        self.__dict__['_socket'] = socket
        self.__dict__['_buffer'] = buffer
        self.__dict__['_timeout'] = socket.gettimeout()

        # We are setting the socket timeout to zero here, regardless of what it
        # was before, because we want to operate the socket in non-blocking
        # mode. This requires some context.
        #
        # Python sockets have three modes: blocking, non-blocking, and timeout.
        # However, "real" sockets only have two: blocking and non-blocking.
        # Internally, Python builds sockets with timeouts by using the select
        # syscall to implement the timeout.
        #
        # We would also like to use select (and friends) in this wrapped
        # socket, so that we can ensure that timeouts apply per
        # ``send``/``recv`` call, as they do with normal Python sockets.
        # However, if we did that without setting the socket timeout to zero
        # we'd end up with *two* selectors for each socket: one used in this
        # class, and one used in the socket. That's gloriously silly. So
        # instead we take responsibility for managing the socket timeout
        # ourselves.
        socket.settimeout(0)

    def _do_read(self, selector, timeout):
        """
        A helper method that performs a read from the network and passes the
        data into the receive buffer.
        """
        selector.modify(self._socket, selectors.EVENT_READ)
        results = selector.select(timeout)

        if not results:
            # TODO: Is there a better way we can throw this?
            raise BlockingIOError()

        assert len(results) == 1
        assert results[0][1] == selectors.EVENT_READ

        # TODO: This can still technically EAGAIN. We need to resolve that.
        data = self._socket.recv(8192)
        if not data:
            return 0
        self._buffer.receive_bytes_from_network(data)
        return len(data)

    def _do_write(self, selector, timeout):
        """
        A helper method that attempts to write all of the data from the send
        buffer to the network. This may make multiple I/O calls, but will not
        spend longer than ``timeout``.
        """
        selector.modify(self._socket, selectors.EVENT_WRITE)

        total_sent = 0
        while True:
            data = self._buffer.peek_bytes(8192)
            if not data:
                break

            with _Timer() as t:
                results = selector.select(timeout)

            if not results:
                # TODO: Is there a better way we can throw this?
                raise BlockingIOError()

            assert len(results) == 1
            assert results[0][1] == selectors.EVENT_WRITE

            # TODO: This can still technically EAGAIN. We need to resolve that.
            sent = self._socket.send(data)
            self._buffer.consume_bytes(sent)
            total_sent += sent

            if timeout is not None:
                timeout -= t.duration

        return total_sent

    def do_handshake(self) -> None:
        timeout = self._timeout

        with selectors.DefaultSelector() as sel:
            sel.register(self._socket, selectors.EVENT_READ)
            while True:
                try:
                    self._buffer.do_handshake()
                except WantReadError:
                    with _Timer() as t:
                        bytes_read = self._do_read(sel, timeout)

                    if not bytes_read:
                        raise TLSError("Unexpected EOF during handshake")

                    if timeout is not None:
                        timeout -= t.duration
                except WantWriteError:
                    with _Timer() as t:
                        self._do_write(sel, timeout)

                    if timeout is not None:
                        timeout -= t.duration
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
        if self._socket is None:
            return None

        self._buffer.shutdown()

        # TODO: So, does unwrap make any sense here? How do we make sure we
        # read up to close_notify, but no further?
        timeout = self._timeout
        with selectors.DefaultSelector() as sel:
            sel.register(self._socket, selectors.EVENT_WRITE)
            while True:
                try:
                    with _Timer() as t:
                        written = self._do_write(sel, timeout)

                    if timeout is not None:
                        timeout -= t.duration
                except ConnectionError:
                    # The socket is not able to tolerate sending, so we're done
                    # here.
                    break
                else:
                    if not written:
                        break

        return self._socket

    def close(self):
        # TODO: we need to do better here with CLOSE_NOTIFY. In particular, we
        # need a way to do a graceful connection shutdown that produces data
        # until the remote party has done CLOSE_NOTIFY.
        self.unwrap()
        self._socket.close()

        # We lose our reference to our socket here so that we can do some
        # short-circuit evaluation elsewhere.
        self._socket = None

    def recv(self, bufsize, flags=0):
        # This method loops in order for blocking sockets to behave correctly
        # when drip-fed data.
        timeout = self._timeout
        with selectors.DefaultSelector() as sel:
            sel.register(self._socket, selectors.EVENT_READ)
            while True:
                # This check is inside the loop because of the possibility that
                # side-effects triggered elsewhere in the loop body could cause
                # a closure.
                if self._socket is None:
                    return b''

                try:
                    return self._buffer.read(bufsize)
                except WantReadError:
                    with _Timer() as t:
                        self._do_read(sel, timeout)

                    if timeout is not None:
                        timeout -= t.duration

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

        with selectors.DefaultSelector() as sel:
            sel.register(self._socket, selectors.EVENT_WRITE)
            sent = self._do_write(sel, self._timeout)
        return sent

    def sendall(self, bytes, flags=0):
        # TODO: Does this obey timeout in the stdlib?
        send_buffer = memoryview(bytes)
        while send_buffer:
            sent = self.send(send_buffer, flags)
            send_buffer = send_buffer[sent:]

        return

    def makefile(self, mode='r', buffering=None, *, encoding=None, errors=None, newline=None):
        pass

    def settimeout(self, timeout):
        self.__dict__['_timeout'] = timeout

    def gettimeout(self):
        return self._timeout

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

        # Also apply any configuration we may have to apply.
        self._process_configuration()

    def _process_configuration(self):
        """
        Given the configuration we got at setup time, handle it.
        """
        # TODO: handle: 'validate_certificates', 'certificate_chain',
        # 'ciphers', 'inner_protocols', 'lowest_supported_version',
        # 'highest_supported_version', 'trust_store'
        config = self._original_context.configuration

        # In either of these cases, we need to break on server auth to take
        # charge of validation. If validate_certificates is False, we will do
        # nothing then: if it's True, then the user has set a custom trust
        # store and we'll do some annoyingly complex work to validate the
        # certs.
        # TODO: What is the oldest supported macOS version? We may need to
        # call the deprecated function SSLSetEnableCertVerify if we must
        # support earlier than 10.8.
        system_trust_stores = (None, _SystemTrustStore)
        if (not config.validate_certificates or
                config.trust_store not in system_trust_stores):
            self._st_context.set_session_option(
                SSLSessionOption.BreakOnServerAuth, True
            )

        # This should be do-able, but requires new bindings. Once again, curl
        # can be our guide here: see CopyIdentityWithLabel and
        # CopyIdentityFromPKSC12File for guidelines. Support for PEM doesn't
        # seem to be present, or even support for loading from separate key and
        # cert (there is a function for loading from a cert and finding a key
        # in the keychain, which isn't the same), but we should investigate
        # whether it can be patched together.
        if config.certificate_chain is not None:
            # do this
            pass

        if config.ciphers is not None:
            # do this
            pass

        # handle lowest supported versions

        if config.trust_store is not None:
            # do this
            pass

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
        # In some instances we need to loop on this handshake (e.g. if we break
        # on server auth.)
        while True:
            try:
                return self._st_context.handshake()
            except WouldBlockError:
                raise self._io_error() from None
            except SecureTransportError as e:
                # We have some error handling we have to do here. Specifically,
                # we want to check whether we're breaking on the server auth
                # here: if we are, we need to do our own handshake.
                if e.error_code is SSLErrors.errSSLServerAuthCompleted:
                    # Here we'd do the cert validation except...right now we
                    # don't know how.
                    # TODO: learn how.
                    continue

                # This isn't something we know how to treat specially. So
                # don't.
                raise

    def cipher(self) -> Optional[CipherSuite]:
        try:
            cipher = self._st_context.get_negotiated_cipher()
        except SecureTransportError:
            return None

        try:
            return CipherSuite(cipher)
        except ValueError:
            return cipher

    def negotiated_protocol(self) -> Optional[Union[NextProtocol, bytes]]:
        """
        SecureTransport does not support ALPN or NPN using any public APIs, so
        this functionality is not supported here.
        """
        return None

    @property
    def context(self) -> SecureTransportClientContext:
        return self._original_context

    def negotiated_tls_version(self) -> Optional[TLSVersion]:
        # We'll need to generalise this stuff.
        mapping = {
            SSLProtocol.SSLProtocolUnknown: None,
            SSLProtocol.SSLProtocol2: TLSVersion.SSLv2,
            SSLProtocol.SSLProtocol3: TLSVersion.SSLv3,
            SSLProtocol.TLSProtocol1: TLSVersion.TLSv1,
            SSLProtocol.TLSProtocol11: TLSVersion.TLSv1_1,
            SSLProtocol.TLSProtocol12: TLSVersion.TLSv1_2,
        }
        try:
            version = self._st_context.get_negotiated_protocol_version()
        except SecureTransportError:
            return None

        return mapping[version]

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
        return _SystemTrustStore

    @classmethod
    def from_pem_file(cls, path):
        # TODO: Ok, so the comment below is not quite right.
        #
        # curl has solved this problem by using
        # kSSLSessionOptionBreakOnServerAuth and then running a custom
        # validator. This will work well. Note that the documentation states
        # that for macOS 10.7 and earlier SecureTransport will not disable its
        # own validation (weirdly). We need to be cautious about older macOS
        # versions here to avoid unexpectedly allowing connections that should
        # be forbidden.
        raise NotImplementedError(
            "SecureTransport does not support PEM bundles as trust stores"
        )


_SystemTrustStore = SecureTransportTrustStore()


SecureTransportBackend = Backend(
    client_context=SecureTransportClientContext, server_context=None,
    certificate=None, private_key=None, trust_store=SecureTransportTrustStore
)
