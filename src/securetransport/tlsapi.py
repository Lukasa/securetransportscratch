# -*- coding: utf-8 -*-
"""
Example implementation of the TLS abstract API using SecureTransport.
"""
from typing import Optional, Any, Union

import socket

from .tls import (
    ClientContext, TLSWrappedSocket, TLSWrappedBuffer, Backend, TrustStore,
    TLSConfiguration, CipherSuite, NextProtocol, TLSVersion
)
from .low_level import (
    SSLSessionContext, SSLProtocolSide, SSLConnectionType, SSLSessionState
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
        return _SecureTransportSocket(socket, server_hostname, self)

    def wrap_buffers(self, incoming: Any, outgoing: Any,
                           server_hostname: Optional[str]) -> TLSWrappedBuffer:
        pass


class _SecureTransportSocket(TLSWrappedSocket):
    """
    A wrapped socket implementation.
    """
    def __init__(self, socket, server_hostname, context):
        self._socket = socket
        self._original_context = context

        self._st_context = SSLSessionContext(
            SSLProtocolSide.Client, SSLConnectionType.StreamType
        )
        self._st_context.set_io_funcs(self._read_func, self._write_func)
        self._st_context.set_connection(socket)
        if server_hostname is not None:
            self._st_context.set_peer_domain_name(server_hostname)

    def _read_func(s, data_to_go):
        """
        The SSL read function.
        """
        # TODO: look at what curl does
        # TODO: handle non-blocking IO here
        data = []

        while data_to_go > 0:
            data_chunk = s.recv(data_to_go)
            data_to_go -= len(data_chunk)
            data.append(data_chunk)

        return 0, b''.join(data)

    def write_func(s, data):
        """
        The SSL write function.
        """
        # TODO: handle non-blocking IO here
        s.sendall(data)
        return 0, len(data)

    def do_handshake(self) -> None:
        self._st_context.handshake()

    def cipher(self) -> Optional[CipherSuite]:
        pass

    def negotiated_protocol(self) -> Optional[Union[NextProtocol, bytes]]:
        pass

    @property
    def context(self) -> SecureTransportClientContext:
        return self._original_context

    @property
    def negotiated_tls_version(self) -> Optional[TLSVersion]:
        pass

    def unwrap(self) -> socket.socket:
        self._st_context.close()
        return self._socket

    def close(self):
        self.unwrap()
        self._socket.close()

    def recv(self, bufsize, flags=None):
        # TODO: restore normal send semantics here.
        return self._st_context.read(bufsize)

    def recv_into(self, buffer, nbytes=None, flags=None):
        # TODO: Work out how to optimise this for SecureTransport
        read_size = nbytes or len(buffer)
        data = self.read(read_size, flags)
        buffer[:len(data)] = data
        return len(data)

    def send(self, data, flags=None):
        # TODO: Restore normal send semantics here.
        return self._st_context.write(data)

    def sendall(self, bytes, flags=None):
        return self._st_context.write(data)

    def makefile(self, mode='r', buffering=None, *, encoding=None, errors=None, newline=None):
        pass

    def __getattr__(self, attribute):
        return getattr(self._socket, attribute)

    def __setattr__(self, attribute, value):
        return setattr(self._socket, attribute, value)


class _SecureTransportBuffer(TLSWrappedBuffer):
    def read(self, amt: Optional[int] = None) -> bytes:
        pass

    def readinto(self, buffer: Any, amt: Optional[int] = None) -> int:
        pass

    def write(self, buf: Any) -> int:
        pass

    def do_handshake(self) -> None:
        pass

    def cipher(self) -> Optional[CipherSuite]:
        pass

    def negotiated_protocol(self) -> Optional[Union[NextProtocol, bytes]]:
        pass

    @property
    def context(self) -> SecureTransportClientContext:
        pass

    def negotiated_tls_version(self) -> Optional[TLSVersion]:
        pass

    def shutdown(self) -> None:
        pass


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
