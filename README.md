openssl-pkcs11-samples
======================

Sample code for working with OpenSSL, LibP11, engine_pkcs11, and OpenSC

Small (close to minimal) single-purpose apps:
---------------------------------------------

[encrypt.c](encrypt.c) -- Software-based encryption.

[sign.c](sign.c) -- Software-based signing.

[tok-sign.c](tok-sign.c) -- Signing with a hardware token.

C++ Wrappers:
-------------

[OpenSSLWrappers.hpp](OpenSSLWrappers.cpp) -- While I still don't
fully understand the lifecycle rules of the OpenSSL+Engine bits, these
classes let me use some amount of
[RAII](http://en.wikipedia.org/wiki/Resource_Acquisition_Is_Initialization)
to help manage lifetimes.
