# -*- coding: utf-8 -*-
"""
Low-level API wrappers for SecureTransport, similar to what PyOpenSSL provides.
Use these if you want to adapt SecureTransport to your I/O model of choice.
"""
import re

import enum

from _securetransport import ffi, lib
from tls import TLSError


class CastableEnum(enum.Enum):
    def __int__(self):
        return self.value


@ffi.def_extern()
def python_read_func(connection, data, data_length):
    """
    The global SSL read function.

    This function just dispatches out to the appropriate methods on the
    given SSLContext.
    """
    context = ffi.from_handle(connection)
    func = context._read_func

    # We need a data buffer to write in to later.
    data = ffi.buffer(data, data_length[0])

    rc, returned_data = func(context.get_connection(), data_length[0])

    data_length[0] = len(returned_data)
    data[:len(returned_data)] = returned_data
    return rc


@ffi.def_extern()
def python_write_func(connection, data, data_length):
    """
    The global SSL write function.

    This function just dispatches out to the appropriate methods on the given
    SSLContext.
    """
    context = ffi.from_handle(connection)
    func = context._write_func

    data_to_write = ffi.buffer(data, data_length[0])[:]
    rc, bytes_written = func(context.get_connection(), data_to_write)
    data_length[0] = bytes_written
    return rc


class SSLProtocolSide(CastableEnum):
    """
    Specifies whether a new SSL context should describe the server side or
    client side of a connection.
    """
    #: Server side.
    Server = lib.kSSLServerSide

    #: Client side.
    Client = lib.kSSLClientSide


class SSLConnectionType(CastableEnum):
    """
    Specifies whether a new SSL context is intended for use in stream-based or
    datagram-based communication.
    """
    #: Stream-based communication (TCP).
    StreamType = lib.kSSLStreamType

    #: Datagram-based communication (UDP).
    DatagramType = lib.kSSLDatagramType


class SSLSessionOption(CastableEnum):
    """
    Options that can be set for an SSL session with the
    :meth:`SSLSessionContext.set_session_option` function.
    """
    #: Enables returning from :meth:`SSLSessionContext.handshake` (with an
    #: exception of errSSLServerAuthCompleted) when the server authentication
    #: portion of the handshake is complete to allow your application to
    #: perform its own certificate verification.
    #:
    #: Note that in iOS (all versions) and OS X 10.8 and later, setting this
    #: option disables Secure Transport's automatic verification of server
    #: certificates.
    #:
    #: If you set this option, your application should perform its own
    #: certificate verification when errSSLServerAuthCompleted is returned
    #: before continuing with the handshake.
    BreakOnServerAuth = lib.kSSLSessionOptionBreakOnServerAuth

    #: Enables returning from :meth:`SSLSessionContext.handshake` (with an
    #: exception of errSSLClientCertRequested) when the server requests a
    #: client certificate.
    BreakOnCertRequested = lib.kSSLSessionOptionBreakOnCertRequested

    #: Enables returning from :meth:`SSLSessionContext.handshake` (with an
    #: exception of errSSLClientAuthCompleted) when the client authentication
    #: portion of the handshake is complete to allow your application to
    #: perform its own certificate verification.
    #:
    #: Note that in iOS (all versions) and OS X 10.8 and later, setting this
    #: option disables Secure Transport's automatic verification of client
    #: certificates.
    #:
    #: If you set this option, your application should perform its own
    #: certificate verification when errSSLClientAuthCompleted is returned
    #: before continuing with the handshake.
    BreakOnClientAuth = lib.kSSLSessionOptionBreakOnClientAuth

    #: When enabled, TLS False Start is used if an adequate cipher-suite is
    #: negotiated.
    FalseStart = lib.kSSLSessionOptionFalseStart

    #: Enables ``1/n-1`` record splitting for BEAST attack mitigation. When
    #: enabled, record splitting is performed only for TLS 1.0 connections
    #: based on a block cipher.
    SendOneByteRecord = lib.kSSLSessionOptionSendOneByteRecord


class SSLAuthenticate(CastableEnum):
    """
    Represents the requirements for client-side authentication.
    """
    #: Indicates that client-side authentication is not required. (Default.)
    Never = lib.kNeverAuthenticate

    #: Indicates that client-side authentication is required.
    Always = lib.kAlwaysAuthenticate

    #: Indicates that client-side authentication should be attempted. There is
    #: no error if the client doesn’t have a certificate.
    Try = lib.kTryAuthenticate


class SSLSessionState(CastableEnum):
    """
    Represents the state of an SSL session.
    """
    #: No I/O has been performed yet.
    Idle = lib.kSSLIdle

    #: The SSL handshake is in progress.
    Handshake = lib.kSSLHandshake

    #: The SSL handshake is complete; the connection is ready for normal I/O.
    Connected = lib.kSSLConnected

    #: The connection closed normally.
    Closed = lib.kSSLClosed

    #: The connection aborted.
    Aborted = lib.kSSLAborted


class SSLProtocol(CastableEnum):
    """
    Represents the SSL protocol version.
    """
    #: Specifies that no protocol has been or should be negotiated or
    #: specified; use default.
    SSLProtocolUnknown = lib.kSSLProtocolUnknown

    #: Specifies that only the SSL 2.0 protocol may be negotiated. Deprecated
    #: in iOS.
    SSLProtocol2 = lib.kSSLProtocol2

    #: Specifies that the SSL 3.0 protocol is preferred; the SSL 2.0 protocol
    #: may be negotiated if the peer cannot use the SSL 3.0 protocol.
    SSLProtocol3 = lib.kSSLProtocol3

    #: Specifies that only the SSL 3.0 protocol may be negotiated; fails if the
    #: peer tries to negotiate the SSL 2.0 protocol. Deprecated in iOS.
    SSLProtocol3Only = lib.kSSLProtocol3Only

    #: Specifies that the TLS 1.0 protocol is preferred but lower versions may
    #: be negotiated.
    TLSProtocol1 = lib.kTLSProtocol1

    #: Specifies that only the TLS 1.0 protocol may be negotiated. Deprecated
    #: in iOS.
    TLSProtocol1Only = lib.kTLSProtocol1Only

    #: Specifies all supported versions. Deprecated in iOS.
    SSLProtocolAll = lib.kSSLProtocolAll

    #: Specifies that the TLS 1.1 protocol is preferred but lower versions may
    #: be negotiated.
    TLSProtocol11 = lib.kTLSProtocol11

    #: Specifies that the TLS 1.2 protocol is preferred but lower versions may
    #: be negotiated.
    TLSProtocol12 = lib.kTLSProtocol12
    DTLSProtocol1 = lib.kDTLSProtocol1


class SSLClientCertificateState(CastableEnum):
    """
    Represents the status of client certificate exchange.
    """
    #: Indicates that the server hasn’t asked for a certificate and that the
    #: client hasn’t sent one.
    ClientCertNone = lib.kSSLClientCertNone

    #: Indicates that the server has asked for a certificate, but the client
    #: has not sent it.
    ClientCertRequested = lib.kSSLClientCertRequested

    #: Indicates that the server asked for a certificate, the client sent one,
    #: and the server validated it. The application can inspect the certificate
    #: using the function :meth:`SSLSessionContext.get_peer_certificates`.
    ClientCertSent = lib.kSSLClientCertSent

    #: Indicates that the client sent a certificate but the certificate failed
    #: validation. This value is seen only on the server side. The server
    #: application can inspect the certificate using the function
    #: :meth:`SSLSessionContext.get_peer_certificates`.
    ClientCertRejected = lib.kSSLClientCertRejected


# The cipher name enum is important too, but there are potentially *loads* of
# values here. Rather than statically manage them, go looking for them. They
# all have the form of this regex except for two,
# TLS_EMPTY_RENEGOTIATION_INFO_SCSV and SSL_NO_SUCH_CIPHERSUITE. Add those
# manually.
_cipher_re = re.compile(r"(SSL|TLS)_[A-Z0-9a-z_]+_WITH_[A-Z0-9a-z_]+")
_cipher_names = [
    name for name in dir(lib) if _cipher_re.match(name) is not None
]
_cipher_names.extend(
    ["TLS_EMPTY_RENEGOTIATION_INFO_SCSV", "SSL_NO_SUCH_CIPHERSUITE"]
)
_enum_values = ((x, getattr(lib, x)) for x in _cipher_names)

#: Represents the cipher suites available.
SSLCipherSuite = CastableEnum("SSLCipherSuite", _enum_values)


#: Represents the error codes that SecureTransport can raise
SSLErrors = CastableEnum(
    "SSLErrors",
    (
        (name, getattr(lib, name))
        for name in dir(lib) if name.startswith('errSSL')
    )
)


class SecureTransportError(TLSError):
    """
    An error occurred in SecureTransport.
    """
    def __init__(self, error_code):
        self.error_code = error_code

        super(SecureTransportError, self).__init__(
            "Encountered error %s" % error_code
        )


class WouldBlockError(SecureTransportError):
    """
    Error raised when a read or write operation would block.
    """
    pass


def _raise_on_error(code):
    """
    Convert the OSStatus error to an exception. Uses the most specific one it
    can find, otherwise raises SecureTransportError.
    """
    if not code:
        return

    if code == lib.errSSLWouldBlock:
        exc = WouldBlockError
    else:
        exc = SecureTransportError

    code = SSLErrors(code)
    raise exc(code)


class SSLSessionContext(object):
    """
    The SSL session context object references the state associated with a
    session. You cannot reuse an SSL session context in multiple sessions.
    """
    def __init__(self, connection_side, socket_type):
        self._connection = None
        self._read_func = None
        self._write_func = None
        self._handle = ffi.new_handle(self)

        # Initialize the SSL context. In particular, we need to set it up to
        # communicate via this class.
        ctx = lib.SSLCreateContext(
            ffi.NULL, connection_side, socket_type
        )
        assert ctx != ffi.NULL
        self._ctx = ffi.gc(ctx, lib.CFRelease)

        status = lib.SSLSetIOFuncs(
            self._ctx, lib.python_read_func, lib.python_write_func
        )
        _raise_on_error(status)

        status = lib.SSLSetConnection(self._ctx, self._handle)
        _raise_on_error(status)

    def set_connection(self, connection):
        """
        Specifies an I/O connection for a specific session.

        This object will be provided to all callbacks registered with this
        class. In particular, it will be provided to the read and write
        callbacks. This object can be as simple as a socket, or as complex as
        an arbitrary Python object. The only requirement is that, given that
        object, data can be read or written.
        """
        # This doesn't translate to a SSLSetConnection call because we need to
        # set ourselves as the connection object to allow the read/write
        # callbacks to proceed appropriately. For that reason, we just store
        # the connection object to replace with ourselves later.
        self._connection = connection

    def get_connection(self):
        """
        Retrieves the previously specified I/O connection.
        """
        return self._connection

    def set_session_option(self, option, value):
        """
        Sets an SSL session option.
        """
        if not isinstance(value, bool):
            raise ValueError("Option must be boolean")
        status = lib.SSLSetSessionOption(self._ctx, option, value)
        _raise_on_error(status)

    def get_session_option(self, option):
        """
        Gets the current value of an SSL session option.
        """
        value = ffi.new("Boolean *")
        status = lib.SSLGetSessionOption(self._ctx, option, value)
        _raise_on_error(status)
        return bool(value[0])

    def set_io_funcs(self, read_func, write_func):
        """
        Sets the read/write functions that will be called by SecureTransport.
        """
        # This doesn't translate to an SSLSetIOFuncs call because of CFFI
        # limitations that mean that there can only be one actual callback.
        # That callback must then dynamically dispatch the callbacks as
        # appropriate. That means that we fake it!
        self._read_func = read_func
        self._write_func = write_func

    def set_client_side_authenticate(self, authenticate):
        """
        Specifies the requirements for client-side authentication.

        A flag setting the requirements for client-side authentication.

        This function can be called only by servers. Use of this function is
        optional. The default authentication requirement is kNeverAuthenticate.
        This function may be called only when no session is active.
        """
        status = lib.SSLSetClientSideAuthenticate(self._ctx, authenticate)
        _raise_on_error(status)

    def handshake(self):
        """
        Performs the SSL handshake.

        On successful return, the session is ready for normal secure
        communication using the functions read and write.

        If it finds any problems with the peer’s certificate chain, Secure
        Transport aborts the handshake. You can use the copy_peer_certificates
        function to see the peer’s certificate chain. This function can raise
        a wide variety of error codes, including the following:

        - errSSLUnknownRootCert: The peer has a valid certificate chain, but
          the root of the chain is not a known anchor certificate.

        - errSSLNoRootCert: The peer’s certificate chain was not verifiable to
          a root certificate.

        - errSSLCertExpired: The peer’s certificate chain has one or more
          expired certificates.

        - errSSLXCertChainInvalid: The peer has an invalid certificate chain;
          for example, signature verification within the chain failed, or no
          certificates were found.

        - errSSLClientCertRequested: The server has requested a client
          certificate. This result is returned only if you called the
          set_session_option function to set the
          kSSLSessionOptionBreakOnCertRequested option. After receiving this
          error, you must call the set_certificate function to return the
          client certificate, and then call handshake again to resume the
          handshake. Use the copy_distinguished_names function to obtain a list
          of certificates acceptable to the server.

        - errSSLServerAuthCompleted: The server authentication portion of the
          handshake is complete. This result is returned only if you called the
          set_session_option function to set the
          kSSLSessionOptionBreakOnServerAuth option, and provides an
          opportunity to perform application-specific server verification
          before calling handshake again to continue.

        Note that in OS X prior to version 10.8, you must also explicitly call
        set_enable_cert_verify to disable verification.

        A exception with a value of errSSLWouldBlock indicates that the
        handshake function must be called again until a different result code
        is returned.
        """
        status = lib.SSLHandshake(self._ctx)
        _raise_on_error(status)

    def get_session_state(self):
        """
        Retrieves the state of an SSL session.

        :returns: A session state enum value.
        """
        state = ffi.new("SSLSessionState *")
        status = lib.SSLGetSessionState(self._ctx, state)
        _raise_on_error(status)
        return SSLSessionState(state[0])

    def get_negotiated_protocol_version(self):
        """
        Obtains the negotiated protocol version of the active session.

        This function retrieves the version of SSL or TLS protocol negotiated
        for the session. Note that the negotiated protocol may not be the same
        as your preferred protocol, depending on which protocol versions you
        enabled with the set_protocol_version_enabled function. This function
        can return any of the following values:

        - kSSLProtocol2
        - kSSLProtocol3
        - kTLSProtocol1
        - kSSLProtocolUnknown
        """
        version = ffi.new("SSLProtocol *")
        status = lib.SSLGetNegotiatedProtocolVersion(self._ctx, version)
        _raise_on_error(status)
        return SSLProtocol(version[0])

    def set_peer_id(self, peer_id_data):
        """
        Specifies data that is sufficient to uniquely identify the peer of the
        current session.

        Secure Transport uses the peer ID to match the peer of an SSL session
        with the peer of a previous session in order to resume an interrupted
        session. If the peer IDs match, Secure Transport attempts to resume the
        session with the same parameters as used in the previous session with
        the same peer.

        The data you provide to this function is treated as an opaque blob by
        Secure Transport but is compared byte for byte with previous peer ID
        data values set by the current application. An example of peer ID data
        is an IP address and port, stored in some caller-private manner.
        Calling this function is optional but is required if you want the
        session to be resumable. If you do call this function, you must call it
        prior to calling handshake for the current session.

        You can use the get_peer_id function to retrieve the peer ID data for
        the current session.

        :param peer_id_data: The peer ID data to set.
        :type peer_id_data: ``bytes``

        :returns: Nothing
        """
        if not isinstance(peer_id_data, bytes):
            raise ValueError("peer_id_data must be a bytestring")

        status = lib.SSLSetPeerID(self._ctx, peer_id_data, len(peer_id_data))
        _raise_on_error(status)

    def get_peer_id(self):
        """
        Retrieves the current peer ID data.

        If the peer ID data for this context was not set by calling the
        set_peer_id function, this function returns None. Otherwise, returns
        the data as opaque bytes.

        :returns: The peer ID binary data, or ``None``.
        """
        peer_id_data = ffi.new("void **")
        peer_id_len = ffi.new("size_t *")
        status = lib.SSLGetPeerID(self._ctx, peer_id_data, peer_id_len)
        _raise_on_error(status)
        return ffi.buffer(peer_id_data[0], peer_id_len[0])[:]

    def get_buffered_read_size(self):
        """
        Determines how much data is available to be read.

        This function determines how much data you can be guaranteed to obtain
        in a call to the read function. This function does not block or cause
        any low-level read operations to occur.
        """
        buffer_size = ffi.new("size_t *")
        status = lib.SSLGetBufferedReadSize(self._ctx, buffer_size)
        _raise_on_error(status)
        return buffer_size[0]

    def read(self, size):
        """
        Performs a normal application-level read operation.

        :param size: The maximum number of bytes to read.
        :type size: ``int``

        :returns: The read bytes.
        :rtype: ``bytes``
        """
        buffer = ffi.new("char[]", size)
        read_count = ffi.new("size_t *")

        status = lib.SSLRead(self._ctx, buffer, size, read_count)

        # We need to catch a weird behaviour here: Apple allows a call to
        # SSLRead to return errSSLWouldBlock but also to have read some data.
        # For our case, we want to consider that as a non-error condition.
        # Short writes are just fine by us.
        read_bytes = read_count[0]
        short_read = (status == lib.errSSLWouldBlock and read_bytes)
        if not short_read:
            _raise_on_error(status)

        return ffi.buffer(buffer, read_bytes)[:]

    def write(self, data):
        """
        Performs a normal application-level write operation.

        :returns: The number of bytes written.
        :rtype: ``int``
        """
        if isinstance(data, memoryview):
            data = data.tobytes()

        write_count = ffi.new("size_t *")
        status = lib.SSLWrite(self._ctx, data, len(data), write_count)

        # We need to catch a weird behaviour here: Apple allows a call to
        # SSLWrite to return errSSLWouldBlock but also to have written some
        # data. For our case, we want to consider that as a non-error
        # condition. Short writes are just fine by us.
        written_bytes = write_count[0]
        short_write = (status == lib.errSSLWouldBlock and written_bytes)

        if not short_write:
            _raise_on_error(status)

        return written_bytes

    def close(self):
        """
        Terminates the current SSL session.
        """
        status = lib.SSLClose(self._ctx)
        _raise_on_error(status)

    def get_supported_ciphers(self):
        """
        Determines the values of the supported cipher suites.

        :returns: A list of supported ciphers, as enum members from
            ``SSLCipherSuites``.
        :rtype: ``list`` of ``SSLCipherSuites``.
        """
        cipher_count = ffi.new("size_t *")
        status = lib.SSLGetNumberSupportedCiphers(self._ctx, cipher_count)
        _raise_on_error(status)

        ciphers = ffi.new("SSLCipherSuite[]", cipher_count[0])
        status = lib.SSLGetSupportedCiphers(self._ctx, ciphers, cipher_count)
        _raise_on_error(status)
        return ciphers[:]

    def set_enabled_ciphers(self, ciphers):
        """
        Specifies a restricted set of SSL cipher suites to be enabled by the
        current SSL session context.

        You can call this function, for example, to limit cipher suites to
        those that use exportable key sizes or to those supported by a
        particular protocol version.

        This function can be called only when no session is active. The default
        set of enabled cipher suites is the complete set of supported cipher
        suites obtained by calling the get_supported_ciphers function.

        Call the get_enabled_ciphers function to determine which SSL cipher
        suites are currently enabled.

        :param ciphers: A list of enum members from ``SSLCipherSuites``
            representing the ciphers to enable.
        :type ciphers: ``list`` of ``SSLCipherSuites``
        """
        ffi_ciphers = ffi.new("SSLCipherSuite[]", ciphers)
        status = lib.SSLSetEnabledCiphers(self._ctx, ffi_ciphers, len(ciphers))
        _raise_on_error(status)

    def get_enabled_ciphers(self):
        """
        Determines which SSL cipher suites are currently enabled.

        :returns: A list of supported ciphers, as enum members from
            ``SSLCipherSuites``.
        :rtype: ``list`` of ``SSLCipherSuites``.
        """
        cipher_count = ffi.new("size_t *")
        status = lib.SSLGetNumberEnabledCiphers(self._ctx, cipher_count)
        _raise_on_error(status)

        ciphers = ffi.new("SSLCipherSuite[]", cipher_count[0])
        status = lib.SSLGetEnabledCiphers(self._ctx, ciphers, cipher_count)
        _raise_on_error(status)
        return ciphers[:]

    def get_negotiated_cipher(self):
        """
        Retrieves the cipher suite negotiated for this session.

        You should call this function only when a session is active.

        :returns: The negotiated cipher.
        :rtype: Member of ``SSLCipherSuites``.
        """
        cipher = ffi.new("SSLCipherSuite *")
        status = lib.SSLGetNegotiatedCipher(self._ctx, cipher)
        _raise_on_error(status)

        return cipher[0]

    def set_diffie_hellman_params(self, params):
        """
        Specifies Diffie-Hellman parameters.

        You can use this function to specify a set of Diffie-Hellman parameters
        to be used by Secure Transport for a specific session. Use of this
        function is optional. If Diffie-Hellman ciphers are allowed, the server
        and client negotiate a Diffie-Hellman cipher, and this function has not
        been called, then Secure Transport calculates a set of process wide
        parameters. However, that process can take as long as 30 seconds.
        Diffie-Hellman ciphers are enabled by default; see set_enabled_ciphers.

        In SSL/TLS, Diffie-Hellman parameters are always specified by the
        server. Therefore, this function can be called only by the server side
        of the connection.

        You can use the get_diffie_hellman_params function to retrieve
        Diffie-Hellman parameters specified in an earlier call to
        set_diffie_hellman_params.

        :param params: Diffie-Hellman parameters in Open SSL DER format.
        :type params: ``bytes``
        """
        if not isinstance(params, bytes):
            raise ValueError("Diffie-Hellman parameters must by bytes.")

        status = lib.SSLSetDiffieHellmanParams(self._ctx, params, len(params))
        _raise_on_error(status)

    def get_diffie_hellman_params(self):
        """
        Retrieves the Diffie-Hellman parameters specified earlier.

        This function returns the parameter block specified in an earlier call
        to the function set_diffie_hellman_params. If set_diffie_hellman_params
        was never called, this function returns None.
        """
        dh_params = ffi.new("void **")
        dh_params_len = ffi.new("size_t *")

        status = lib.SSLGetDiffieHellmanParams(
            self._ctx, dh_params, dh_params_len
        )
        _raise_on_error(status)

        if dh_params[0] == ffi.NULL:
            return None

        return dh_params[0][:dh_params_len[0]]

    def set_peer_domain_name(self, name):
        """
        Specifies the fully qualified domain name of the peer.

        :param name: The fully-qualified domain name of the peer, as a byte
            string.
        :type name: ``bytes``
        """
        if not isinstance(name, bytes):
            raise ValueError("name must be a byte string")

        status = lib.SSLSetPeerDomainName(self._ctx, name, len(name))
        _raise_on_error(status)

    def get_peer_domain_name(self):
        """
        Retrieves the peer domain name specified previously.
        """
        length = ffi.new("size_t *")
        status = lib.SSLGetPeerDomainNameLength(self._ctx, length)
        _raise_on_error(status)

        name = ffi.new("char[]", length[0])
        status = lib.SSLGetPeerDomainName(self._ctx, name, length)
        _raise_on_error(status)

        return name[:length[0]]
