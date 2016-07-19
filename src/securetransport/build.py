# -*- coding: utf-8 -*-
"""
CFFI API for SecureTransport.
"""

from cffi import FFI
ffibuilder = FFI()

ffibuilder.set_source(
    "_securetransport",
    "#include <Security/SecureTransport.h>",
    extra_link_args=['-framework', 'Security'],
)

ffibuilder.cdef(
    """
    typedef ... *CFAllocatorRef;
    typedef ... *SSLContextRef;

    typedef enum {
        kSSLServerSide,
        kSSLClientSide
    } SSLProtocolSide;

    typedef enum {
        kSSLStreamType,
        kSSLDatagramType
    } SSLConnectionType;

    SSLContextRef SSLCreateContext(CFAllocatorRef alloc,
                                   SSLProtocolSide protocolSide,
                                   SSLConnectionType connectionType);
""")

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
