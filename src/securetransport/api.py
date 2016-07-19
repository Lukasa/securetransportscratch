# -*- coding: utf-8 -*-
"""
Sample APIs for having a "SSLContext" and "SSLSocket" built on top of
SecureTransport.
"""
import ssl


class SecureTransportContext(object):
    """
    An SSLContext equivalent for SecureTransport.
    """
    def __init__(self, protocol):
        # TODO: implement!
        pass

    def load_cert_chain(self, certfile, keyfile=None, password=None):
        """
        Load a private key and the corresponding certificate. The certfile
        string must be the path to a single file in PEM format containing the
        certificate as well as any number of CA certificates needed to
        establish the certificate’s authenticity. The keyfile string, if
        present, must point to a file containing the private key in. Otherwise
        the private key will be taken from certfile as well.

        The password argument may be a function to call to get the password for
        decrypting the private key. It will only be called if the private key
        is encrypted and a password is necessary. It will be called with no
        arguments, and it should return a string, bytes, or bytearray. If the
        return value is a string it will be encoded as UTF-8 before using it to
        decrypt the key. Alternatively a string, bytes, or bytearray value may
        be supplied directly as the password argument. It will be ignored if
        the private key is not encrypted and no password is needed.
        """
        # TODO: implement!
        pass

    def load_default_certs(self, purpose=ssl.Purpose.SERVER_AUTH):
        """
        Load a set of default “certification authority” (CA) certificates from
        default locations.
        """
        # TODO: implement if needed!
        pass

    def load_verify_locations(cafile=None, capath=None, cadata=None):
        """
        Load a set of “certification authority” (CA) certificates used to
        validate other peers’ certificates when verify_mode is other than
        CERT_NONE.
        """
        # TODO: implement
        pass

    def set_ciphers(self, ciphers):
        """
        Set the available ciphers for sockets created with this context. It
        should be a string in the OpenSSL cipher list format. If no cipher can
        be selected (because compile-time options or other configuration
        forbids use of all the specified ciphers), an SSLError will be raised.
        """
        # TODO: implement
        pass

    def set_alpn_protocols(self, protocols):
        """
        Specify which protocols the socket should advertise during the SSL/TLS
        handshake. It should be a list of ASCII strings, like
        ['http/1.1', 'spdy/2'], ordered by preference. The selection of a
        protocol will happen during the handshake, and will play out according
        to RFC 7301. After a successful handshake, the
        SecureTransportSocket.selected_alpn_protocol() method will return the
        agreed-upon protocol.

        This method will raise NotImplementedError if HAS_ALPN is False.
        """
        # TODO: implement
        pass

    def set_npn_protocols(self, protocols):
        """
        Specify which protocols the socket should advertise during the SSL/TLS
        handshake. It should be a list of strings, like ['http/1.1', 'spdy/2'],
        ordered by preference. The selection of a protocol will happen during
        the handshake, and will play out according to the NPN draft
        specification. After a successful handshake, the
        SecureTransportSocket.selected_npn_protocol() method will return the
        agreed-upon protocol.

        This method will raise NotImplementedError if HAS_NPN is False.
        """
        # TODO: implement
        pass

    def load_dh_params(self, dhfile):
        """
        Load the key generation parameters for Diffie-Helman (DH) key exchange.
        Using DH key exchange improves forward secrecy at the expense of
        computational resources (both on the server and on the client). The
        dhfile parameter should be the path to a file containing DH parameters
        in PEM format.

        This setting doesn’t apply to client sockets. You can also use the
        OP_SINGLE_DH_USE option to further improve security.
        """
        # TODO: implement
        pass

    def wrap_socket(self, sock, server_side=False,
                    do_handshake_on_connect=True, suppress_ragged_eofs=True,
                    server_hostname=None):
        """
        Wrap an existing Python socket sock and return a SecureTransportSocket
        object. sock must be a SOCK_STREAM socket; other socket types are
        unsupported.

        The returned SSL socket is tied to the context, its settings and
        certificates.

        On client connections, the optional parameter server_hostname specifies
        the hostname of the service which we are connecting to. This allows a
        single server to host multiple SSL-based services with distinct
        certificates, quite similarly to HTTP virtual hosts. Specifying
        server_hostname will raise a ValueError if server_side is true.
        """
        # TODO: implement
        pass

    @property
    def options(self):
        """
        An integer representing the set of SSL options enabled on this context.
        The default value is OP_ALL, but you can specify other options such as
        OP_NO_SSLv2 by ORing them together.
        """
        # TODO: implement
        pass

    @options.setter
    def options(self, value):
        """
        An integer representing the set of SSL options enabled on this context.
        The default value is OP_ALL, but you can specify other options such as
        OP_NO_SSLv2 by ORing them together.
        """
        # TODO: implement
        pass

    @property
    def protocol(self):
        """
        The protocol version chosen when constructing the context. This
        attribute is read-only.
        """
        # TODO: implement
        pass

    @property
    def verify_mode(self):
        """
        Whether to try to verify other peers’ certificates and how to behave if
        verification fails. This attribute must be one of CERT_NONE,
        CERT_OPTIONAL or CERT_REQUIRED.
        """
        # TODO: implement
        pass

    @verify_mode.setter
    def verify_mode(self, setter):
        """
        Whether to try to verify other peers’ certificates and how to behave if
        verification fails. This attribute must be one of CERT_NONE,
        CERT_OPTIONAL or CERT_REQUIRED.
        """
        # TODO: implement
        pass


class SecureTransportSocket(object):
    """
    A SSLSocket equivalent for SecureTransport.
    """
