/**
 * @file OpenSSLWrappersTest.cpp
 *
 * @author Anthony Foiani <anthony@foiani.com>
 *
 * @copyright 2013
 *
 * @license Boost Public License v1.0
 */

#include <boost/test/minimal.hpp>

#include "OpenSSLWrappers.hpp"

int
test_main( int /* argc */, char * /* argv */ [] )
{
    OpenSSL::Environment env;

    {
        OpenSSL::Engine engine;
    }

#if USE_CRYPTODEV
    {
        OpenSSL::CryptoDevEngine cde( 0 );
    }
#endif // USE_CRYPTODEV

    {
        OpenSSL::DynamicEngine dyn(
            "pkcs11",
            { "/opt/crypto/lib/engines/engine_pkcs11.so", "/lib/engines/engine_pkcs11.so" }
        );
    }

    {
        OpenSSL::TokenEngine tok( { "/opt/crypto/lib/opensc-pkcs11.so", "/lib/opensc-pkcs11.so" } );
    }

    return boost::exit_success;
}
