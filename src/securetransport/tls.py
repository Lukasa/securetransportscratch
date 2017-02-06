# -*- coding: utf-8 -*-
"""
A WIP example of the TLS API from the TLS ABC PEP.
"""
from typing import Callable, Optional, Any, Tuple, Union, AnyStr

import pathlib
import socket

from abc import ABCMeta, abstractmethod, abstractproperty, abstractclassmethod
from collections import namedtuple
from enum import Enum, auto


_configuration_fields = [
    'validate_certificates',
    'certificate_chain',
    'ciphers',
    'inner_protocols',
    'lowest_supported_version',
    'highest_supported_version',
    'trust_store',
    'sni_callback',
]


_DEFAULT_VALUE = object()


class CipherSuite(IntEnum):
    TLS_RSA_WITH_RC4_128_SHA = 0x0005
    TLS_RSA_WITH_IDEA_CBC_SHA = 0x0007
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000a
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = 0x0010
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x0016
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f
    TLS_DH_RSA_WITH_AES_128_CBC_SHA = 0x0031
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035
    TLS_DH_RSA_WITH_AES_256_CBC_SHA = 0x0037
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003c
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003d
    TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = 0x003f
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0041
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0043
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0045
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = 0x0069
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006b
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0084
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0086
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0088
    TLS_RSA_WITH_SEED_CBC_SHA = 0x0096
    TLS_DH_RSA_WITH_SEED_CBC_SHA = 0x0098
    TLS_DHE_RSA_WITH_SEED_CBC_SHA = 0x009a
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009c
    TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009d
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009e
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009f
    TLS_DH_RSA_WITH_AES_128_GCM_SHA256 = 0x00a0
    TLS_DH_RSA_WITH_AES_256_GCM_SHA384 = 0x00a1
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00ba
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00bc
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00be
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00c0
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00c2
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00c4
    TLS_AES_128_GCM_SHA256 = 0x1301
    TLS_AES_256_GCM_SHA384 = 0x1302
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303
    TLS_AES_128_CCM_SHA256 = 0x1304
    TLS_AES_128_CCM_8_SHA256 = 0x1305
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA = 0xc002
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xc003
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = 0xc004
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = 0xc005
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = 0xc007
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xc008
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xc009
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xc00a
    TLS_ECDH_RSA_WITH_RC4_128_SHA = 0xc00c
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = 0xc00d
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = 0xc00e
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = 0xc00f
    TLS_ECDHE_RSA_WITH_RC4_128_SHA = 0xc011
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = 0xc012
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xc013
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xc014
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xc023
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xc024
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = 0xc025
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = 0xc026
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xc027
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xc028
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = 0xc029
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = 0xc02a
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c
    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02d
    TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02e
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = 0xc031
    TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = 0xc032
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xc072
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xc073
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xc074
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xc075
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xc076
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xc077
    TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xc078
    TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xc079
    TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc07a
    TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc07b
    TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc07c
    TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc07d
    TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc07e
    TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc07f
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc086
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc087
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc088
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc089
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc08a
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc08b
    TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xc08c
    TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xc08d
    TLS_RSA_WITH_AES_128_CCM = 0xc09c
    TLS_RSA_WITH_AES_256_CCM = 0xc09d
    TLS_DHE_RSA_WITH_AES_128_CCM = 0xc09e
    TLS_DHE_RSA_WITH_AES_256_CCM = 0xc09f
    TLS_RSA_WITH_AES_128_CCM_8 = 0xc0a0
    TLS_RSA_WITH_AES_256_CCM_8 = 0xc0a1
    TLS_DHE_RSA_WITH_AES_128_CCM_8 = 0xc0a2
    TLS_DHE_RSA_WITH_AES_256_CCM_8 = 0xc0a3
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM = 0xc0ac
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM = 0xc0ad
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = 0xc0ae
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = 0xc0af
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca8
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xccaa


class NextProtocol(Enum):
    H2 = b'h2'
    H2C = b'h2c'
    HTTP1 = b'http/1.1'
    WEBRTC = b'webrtc'
    C_WEBRTC = b'c-webrtc'
    FTP = b'ftp'
    STUN = b'stun.nat-discovery'
    TURN = b'stun.turn'


class TLSVersion(Enum):
    MINIMUM_SUPPORTED = auto()
    SSLv2 = auto()
    SSLv3 = auto()
    TLSv1 = auto()
    TLSv1_1 = auto()
    TLSv1_2 = auto()
    TLSv1_3 = auto()
    MAXIMUM_SUPPORTED = auto()


class Certificate(metaclass=ABCMeta):
    @abstractclassmethod
    def from_buffer(cls, buffer: bytes):
        """
        Creates a Certificate object from a byte buffer. This byte buffer
        may be either PEM-encoded or DER-encoded. If the buffer is PEM
        encoded it *must* begin with the standard PEM preamble (a series of
        dashes followed by the ASCII bytes "BEGIN CERTIFICATE" and another
        series of dashes). In the absence of that preamble, the
        implementation may assume that the certificate is DER-encoded
        instead.
        """

    @abstractclassmethod
    def from_file(cls, path: Union[pathlib.Path, AnyStr]):
        """
        Creates a Certificate object from a file on disk. This method may
        be a convenience method that wraps ``open`` and ``from_buffer``,
        but some TLS implementations may be able to provide more-secure or
        faster methods of loading certificates that do not involve Python
        code.
        """


class PrivateKey(metaclass=ABCMeta):
    @abstractclassmethod
    def from_buffer(cls,
                    buffer: bytes,
                    password: Optional[Union[Callable[[], Union[bytes, bytearray]], bytes, bytearray]] = None):
        """
        Creates a PrivateKey object from a byte buffer. This byte buffer
        may be either PEM-encoded or DER-encoded. If the buffer is PEM
        encoded it *must* begin with the standard PEM preamble (a series of
        dashes followed by the ASCII bytes "BEGIN", the key type, and
        another series of dashes). In the absence of that preamble, the
        implementation may assume that the certificate is DER-encoded
        instead.

        The key may additionally be encrypted. If it is, the ``password``
        argument can be used to decrypt the key. The ``password`` argument
        may be a function to call to get the password for decrypting the
        private key. It will only be called if the private key is encrypted
        and a password is necessary. It will be called with no arguments,
        and it should return either bytes or bytearray containing the
        password. Alternatively a bytes, or bytearray value may be supplied
        directly as the password argument. It will be ignored if the
        private key is not encrypted and no password is needed.
        """

    @abstractclassmethod
    def from_file(cls,
                  path: Union[pathlib.Path, bytes, str],
                  password: Optional[Union[Callable[[], Union[bytes, bytearray]], bytes, bytearray]] = None):
        """
        Creates a PrivateKey object from a file on disk. This method may
        be a convenience method that wraps ``open`` and ``from_buffer``,
        but some TLS implementations may be able to provide more-secure or
        faster methods of loading certificates that do not involve Python
        code.

        The ``password`` parameter behaves exactly as the equivalent
        parameter on ``from_buffer``.
        """


class TrustStore(metaclass=ABCMeta):
    @abstractclassmethod
    def system(cls):
        """
        Returns a TrustStore object that represents the system trust
        database.
        """

    @abstractclassmethod
    def from_pem_file(cls, path: Union[pathlib.Path, bytes, str]):
        """
        Initializes a trust store from a single file full of PEMs.
        """


Backend = namedtuple(
    'Backend',
    ['client_context', 'server_context',
        'certificate', 'private_key', 'trust_store']
)


class TLSWrappedSocket(metaclass=ABCMeta):
    # The various socket methods all must be implemented. Their definitions
    # have been elided from this class defintion in the PEP because they
    # aren't instructive.
    @abstractmethod
    def do_handshake(self) -> None:
        """
        Performs the TLS handshake. Also performs certificate validation
        and hostname verification.
        """

    @abstractmethod
    def cipher(self) -> Optional[CipherSuite]:
        """
        Returns the CipherSuite entry for the cipher that has been
        negotiated on the connection. If no connection has been negotiated,
        returns ``None``.
        """

    @abstractmethod
    def negotiated_protocol(self) -> Optional[Union[NextProtocol, bytes]]:
        """
        Returns the protocol that was selected during the TLS handshake.
        This selection may have been made using ALPN, NPN, or some future
        negotiation mechanism.

        If the negotiated protocol is one of the protocols defined in the
        ``NextProtocol`` enum, the value from that enum will be returned.
        Otherwise, the raw bytestring of the negotiated protocol will be
        returned.

        If ``Context.set_inner_protocols()`` was not called, if the other
        party does not support protocol negotiation, if this socket does
        not support any of the peer's proposed protocols, or if the
        handshake has not happened yet, ``None`` is returned.
        """

    @property
    @abstractmethod
    def context(self):
        """
        The ``_BaseContext`` object this socket is tied to.
        """

    @abstractproperty
    def negotiated_tls_version(self) -> Optional[TLSVersion]:
        """
        The version of TLS that has been negotiated on this connection.
        """

    @abstractmethod
    def unwrap(self) -> socket.socket:
        """
        Cleanly terminate the TLS connection on this wrapped socket. Once
        called, this ``TLSWrappedSocket`` can no longer be used to transmit
        data. Returns the socket that was wrapped with TLS.
        """


class TLSWrappedBuffer(metaclass=ABCMeta):
    @abstractmethod
    def read(self, amt: Optional[int] = None) -> bytes:
        """
        Read up to ``amt`` bytes of data from the input buffer and return
        the result as a ``bytes`` instance. If ``amt`` is ``None``, will
        attempt to read until either EOF is reached or until further
        attempts to read would raise either ``WantReadError`` or
        ``WantWriteError``.

        Raise ``WantReadError`` or ``WantWriteError`` if there is
        insufficient data in either the input or output buffer and the
        operation would have caused data to be written or read.

        As at any time a re-negotiation is possible, a call to ``read()``
        can also cause write operations.
        """

    @abstractmethod
    def readinto(self, buffer: Any, amt: Optional[int] = None) -> int:
        """
        Read up to ``amt`` bytes of data from the input buffer into
        ``buffer``, which must be an object that implements the buffer
        protocol. Returns the number of bytes read. If ``amt`` is ``None``,
        will attempt to read until either EOF is reached or until further
        attempts to read would raise either ``WantReadError`` or
        ``WantWriteError``, or until the buffer is full.

        Raises ``WantReadError`` or ``WantWriteError`` if there is
        insufficient data in either the input or output buffer and the
        operation would have caused data to be written or read.

        As at any time a re-negotiation is possible, a call to
        ``readinto()`` can also cause write operations.
        """

    @abstractmethod
    def write(self, buf: Any) -> int:
        """
        Write ``buf`` in encrypted form to the output buffer and return the
        number of bytes written. The ``buf`` argument must be an object
        supporting the buffer interface.

        Raise ``WantReadError`` or ``WantWriteError`` if there is
        insufficient data in either the input or output buffer and the
        operation would have caused data to be written or read.

        As at any time a re-negotiation is possible, a call to ``write()``
        can also cause read operations.
        """

    @abstractmethod
    def do_handshake(self) -> None:
        """
        Performs the TLS handshake. Also performs certificate validation
        and hostname verification.
        """

    @abstractmethod
    def cipher(self) -> Optional[CipherSuite]:
        """
        Returns the CipherSuite entry for the cipher that has been
        negotiated on the connection. If no connection has been negotiated,
        returns ``None``.
        """

    @abstractmethod
    def negotiated_protocol(self) -> Optional[Union[NextProtocol, bytes]]:
        """
        Returns the protocol that was selected during the TLS handshake.
        This selection may have been made using ALPN, NPN, or some future
        negotiation mechanism.

        If the negotiated protocol is one of the protocols defined in the
        ``NextProtocol`` enum, the value from that enum will be returned.
        Otherwise, the raw bytestring of the negotiated protocol will be
        returned.

        If ``Context.set_inner_protocols()`` was not called, if the other
        party does not support protocol negotiation, if this socket does
        not support any of the peer's proposed protocols, or if the
        handshake has not happened yet, ``None`` is returned.
        """

    @property
    @abstractmethod
    def context(self):
        """
        The ``_BaseContext`` object this socket is tied to.
        """

    @abstractproperty
    def negotiated_tls_version(self) -> Optional[TLSVersion]:
        """
        The version of TLS that has been negotiated on this connection.
        """

    @abstractmethod
    def shutdown(self) -> None:
        """
        Performs a clean TLS shut down. This should generally be used
        whenever possible to signal to the remote peer that the content is
        finished.
        """



class TLSError(Exception):
    """
    The base exception for all TLS related errors from any backend.
    Catching this error should be sufficient to catch *all* TLS errors,
    regardless of what backend is used.
    """


class WantWriteError(TLSError):
    """
    A special signaling exception used only when non-blocking or
    buffer-only I/O is used. This error signals that the requested
    operation cannot complete until more data is written to the network,
    or until the output buffer is drained.
    """


class WantReadError(TLSError):
    """
    A special signaling exception used only when non-blocking or
    buffer-only I/O is used. This error signals that the requested
    operation cannot complete until more data is read from the network, or
    until more data is available in the input buffer.
    """


TLSBufferObject = Union[TLSWrappedSocket, TLSWrappedBuffer]


class TLSConfiguration(namedtuple('TLSConfiguration', _configuration_fields)):
    """
    An immutable TLS Configuration object. This object has the following
    properties:

    :param validate_certificates bool: Whether to validate the TLS
        certificates. This switch operates at a very broad scope: either
        validation is enabled, in which case all forms of validation are
        performed including hostname validation if possible, or validation
        is disabled, in which case no validation is performed.

        Not all backends support having their certificate validation
        disabled. If a backend does not support having their certificate
        validation disabled, attempting to set this property to ``False``
        will throw a ``TLSError`` when this object is passed into a
        context object.

    :param certificate_chain Tuple[Tuple[Certificate],PrivateKey]: The
        certificate, intermediate certificate, and the corresponding
        private key for the leaf certificate. These certificates will be
        offered to the remote peer during the handshake if required.

        The first Certificate in the list must be the leaf certificate. All
        subsequent certificates will be offered as intermediate additional
        certificates.

    :param ciphers Tuple[CipherSuite]:
        The available ciphers for TLS connections created with this
        configuration, in priority order.

    :param inner_protocols Tuple[Union[NextProtocol, bytes]]:
        Protocols that connections created with this configuration should
        advertise as supported during the TLS handshake. These may be
        advertised using either or both of ALPN or NPN. This list of
        protocols should be ordered by preference.

    :param lowest_supported_version TLSVersion:
        The minimum version of TLS that should be allowed on TLS
        connections using this configuration.

    :param highest_supported_version TLSVersion:
        The maximum version of TLS that should be allowed on TLS
        connections using this configuration.

    :param trust_store TrustStore:
        The trust store that connections using this configuration will use
        to validate certificates.

    :param sni_callback Optional[ServerNameCallback]:
        A callback function that will be called after the TLS Client Hello
        handshake message has been received by the TLS server when the TLS
        client specifies a server name indication.

        Only one callback can be set per ``TLSConfiguration``. If the
        ``sni_callback`` is ``None`` then the callback is disabled. If the
        ``TLSConfiguration`` is used for a ``ClientContext`` then this
        setting will be ignored.

        The ``callback`` function will be called with three arguments: the
        first will be the ``TLSBufferObject`` for the connection; the
        second will be a string that represents the server name that the
        client is intending to communicate (or ``None`` if the TLS Client
        Hello does not contain a server name); and the third argument will
        be the original ``Context``. The server name argument will be the
        IDNA *decoded* server name.

        The ``callback`` must return a ``TLSConfiguration`` to allow
        negotiation to continue. Other return values signal errors.
        Attempting to control what error is signaled by the underlying TLS
        implementation is not specified in this API, but is up to the
        concrete implementation to handle.

        The Context will do its best to apply the ``TLSConfiguration``
        changes from its original configuration to the incoming connection.
        This will usually include changing the certificate chain, but may
        also include changes to allowable ciphers or any other
        configuration settings.
    """
    __slots__ = ()

    def __new__(cls, validate_certificates: Optional[bool] = None,
                     certificate_chain: Optional[Tuple[Tuple[Certificate], PrivateKey]] = None,
                     ciphers: Optional[Tuple[CipherSuite]] = None,
                     inner_protocols: Optional[Tuple[Union[NextProtocol, bytes]]] = None,
                     lowest_supported_version: Optional[TLSVersion] = None,
                     highest_supported_version: Optional[TLSVersion] = None,
                     trust_store: Optional[TrustStore] = None,
                     sni_callback=None):

        if validate_certificates is None:
            validate_certificates = True

        if ciphers is None:
            ciphers = DEFAULT_CIPHER_LIST

        if inner_protocols is None:
            inner_protocols = []

        if lowest_supported_version is None:
            lowest_supported_version = TLSVersion.TLSv1

        if highest_supported_version is None:
            highest_supported_version = TLSVersion.MAXIMUM_SUPPORTED

        return super().__new__(
            cls, validate_certificates, certificate_chain, ciphers,
            inner_protocols, lowest_supported_version,
            highest_supported_version, trust_store, sni_callback
        )

    def update(self, validate_certificates=_DEFAULT_VALUE,
                     certificate_chain=_DEFAULT_VALUE,
                     ciphers=_DEFAULT_VALUE,
                     inner_protocols=_DEFAULT_VALUE,
                     lowest_supported_version=_DEFAULT_VALUE,
                     highest_supported_version=_DEFAULT_VALUE,
                     trust_store=_DEFAULT_VALUE,
                     sni_callback=_DEFAULT_VALUE):
        """
        Create a new ``TLSConfiguration``, overriding some of the settings
        on the original configuration with the new settings.
        """
        if validate_certificates is _DEFAULT_VALUE:
            validate_certificates = self.validate_certificates

        if certificate_chain is _DEFAULT_VALUE:
            certificate_chain = self.certificate_chain

        if ciphers is _DEFAULT_VALUE:
            ciphers = self.ciphers

        if inner_protocols is _DEFAULT_VALUE:
            inner_protocols = self.inner_protocols

        if lowest_supported_version is _DEFAULT_VALUE:
            lowest_supported_version = self.lowest_supported_version

        if highest_supported_version is _DEFAULT_VALUE:
            highest_supported_version = self.highest_supported_version

        if trust_store is _DEFAULT_VALUE:
            trust_store = self.trust_store

        if sni_callback is _DEFAULT_VALUE:
            sni_callback = self.sni_callback

        return self.__class__(
            validate_certificates, certificate_chain, ciphers,
            inner_protocols, lowest_supported_version,
            highest_supported_version, trust_store, sni_callback
        )



class _BaseContext(metaclass=ABCMeta):
    @abstractmethod
    def __init__(self, configuration: TLSConfiguration):
        """
        Create a new context object from a given TLS configuration.
        """

    @property
    @abstractmethod
    def configuration(self) -> TLSConfiguration:
        """
        Returns the TLS configuration that was used to create the context.
        """


class ClientContext(_BaseContext):
    @abstractmethod
    def wrap_socket(self,
                    socket: socket.socket,
                    server_hostname: Optional[str],
                    auto_handshake: bool = True) -> TLSWrappedSocket:
        """
        Wrap an existing Python socket object ``socket`` and return a
        ``TLSWrappedSocket`` object. ``socket`` must be a ``SOCK_STREAM``
        socket: all other socket types are unsupported.

        The returned SSL socket is tied to the context, its settings and
        certificates.

        The parameter ``server_hostname`` specifies the hostname of the
        service which we are connecting to. This allows a single server to
        host multiple SSL-based services with distinct certificates, quite
        similarly to HTTP virtual hosts. This is also used to validate the
        TLS certificate for the given hostname. If hostname validation is
        not desired, then pass ``None`` for this parameter.

        The parameter ``auto_handshake`` specifies whether to do the SSL
        handshake automatically after doing a ``socket.connect()``, or
        whether the application program will call it explicitly, by
        invoking the ``TLSWrappedSocket.do_handshake()`` method. Calling
        ``TLSWrappedSocket.do_handshake()`` explicitly gives the program
        control over the blocking behavior of the socket I/O involved in
        the handshake.
        """

    @abstractmethod
    def wrap_buffers(self, incoming: Any, outgoing: Any,
                     server_hostname: Optional[str]) -> TLSWrappedBuffer:
        """
        Wrap a pair of buffer objects (``incoming`` and ``outgoing``) to
        create an in-memory stream for TLS. The SSL routines will read data
        from ``incoming`` and decrypt it, and write encrypted data to
        ``outgoing``.

        The buffer objects must be either file objects or objects that
        implement the buffer protocol.

        The ``server_hostname`` parameter has the same meaning as in
        ``wrap_socket``.
        """


class ServerContext(_BaseContext):
    @abstractmethod
    def wrap_socket(self, socket: socket.socket,
                    auto_handshake: bool = True) -> TLSWrappedSocket:
        """
        Wrap an existing Python socket object ``socket`` and return a
        ``TLSWrappedSocket`` object. ``socket`` must be a ``SOCK_STREAM``
        socket: all other socket types are unsupported.

        The returned SSL socket is tied to the context, its settings and
        certificates.

        The parameter ``auto_handshake`` specifies whether to do the SSL
        handshake automatically after doing a ``socket.accept()``, or
        whether the application program will call it explicitly, by
        invoking the ``TLSWrappedSocket.do_handshake()`` method. Calling
        ``TLSWrappedSocket.do_handshake()`` explicitly gives the program
        control over the blocking behavior of the socket I/O involved in
        the handshake.
        """

    @abstractmethod
    def wrap_buffers(self, incoming: Any, outgoing: Any) -> TLSWrappedBuffer:
        """
        Wrap a pair of buffer objects (``incoming`` and ``outgoing``) to
        create an in-memory stream for TLS. The SSL routines will read data
        from ``incoming`` and decrypt it, and write encrypted data to
        ``outgoing``.

        The buffer objects must be either file objects or objects that
        implement the buffer protocol.
        """
