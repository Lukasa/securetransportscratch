# -*- coding: utf-8 -*-
"""
CFFI API for SecureTransport.
"""

from cffi import FFI
ffibuilder = FFI()

ffibuilder.set_source(
    "_securetransport",
    """
    #include <stdlib.h>
    #include <Security/SecureTransport.h>
    """,
    extra_link_args=['-framework', 'Security'],
)

ffibuilder.cdef(
    """
    typedef signed long OSStatus;
    typedef ... *CFAllocatorRef;
    typedef ... *SSLContextRef;
    typedef ... *SSLConnectionRef;

    typedef enum {
        kSSLServerSide,
        kSSLClientSide
    } SSLProtocolSide;

    typedef enum {
        kSSLStreamType,
        kSSLDatagramType
    } SSLConnectionType;

    typedef OSStatus (*SSLReadFunc) (SSLConnectionRef, void *, size_t *);
    typedef OSStatus (*SSLWriteFunc) (SSLConnectionRef,
                                      const void *,
                                      size_t *);

    SSLContextRef SSLCreateContext(CFAllocatorRef,
                                   SSLProtocolSide,
                                   SSLConnectionType);

    OSStatus SSLSetIOFuncs(SSLContextRef,
                           SSLReadFunc,
                           SSLWriteFunc);

    OSStatus SSLSetConnection (SSLContextRef, SSLConnectionRef);

    OSStatus SSLSetPeerDomainName (SSLContextRef, const char *, size_t);

    extern "Python" OSStatus python_read_func(SSLConnectionRef,
                                              void *,
                                              size_t*);

    extern "Python" OSStatus python_write_func(SSLConnectionRef,
                                               void *,
                                               size_t*);
""")

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
