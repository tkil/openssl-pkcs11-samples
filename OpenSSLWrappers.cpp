/**
 * @file OpenSSLWrappers.cpp
 *
 * @author Anthony Foiani <anthony@foiani.com>
 *
 * @copyright 2013
 *
 * @license Boost Public License v1.0
 */

// standard C headers
#include "fcntl.h"

// openssl headers
#include <openssl/bio.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

// standard C++ headers
#include <iostream>
#include <sstream>

// boost headers
#include <boost/filesystem.hpp>
#include <boost/io/ios_state.hpp>

// interface
#include "OpenSSLWrappers.hpp"

// =====================================================================

#define OPENSSL_WRAPPERS_DEBUG 1

#if OPENSSL_WRAPPERS_DEBUG

#define DEBUG( x )                                      \
    do {                                                \
        boost::io::ios_all_saver ias( std::clog );      \
        std::clog << "ossl-wrp: " << x << std::endl;    \
    } while ( 0 )

#else

#define DEBUG( x ) do {} while ( 0 )

#endif

#if OPENSSL_WRAPPERS_DEBUG > 1

#  define DEBUG_FINE( x )                               \
    do {                                                \
        boost::io::ios_all_saver ias( std::clog );      \
        std::clog << "ossl-wrp: > " << x << std::endl;  \
    } while ( 0 )
#  define DEBUG_FINE_ONLY( x ) x

#else

#  define DEBUG_FINE( x ) do {} while ( 0 )
#  define DEBUG_FINE_ONLY( x )

#endif

// =====================================================================

namespace // anonymous
{

using namespace OpenSSL;

// "quote string"
string
QS( const string & src )
{
    static char hex[] = "0123456789abcdef";
    string rv;
    rv.reserve( src.size() + 2 );
    rv.append( "'" );

    for ( const char c : src )
    {
        if ( std::isprint( c ) )
        {
            rv.push_back( c );
        }
        else
        {
            rv.push_back( '\\' );
            rv.push_back( 'x'  );
            rv.push_back( hex[ ( c >> 4 ) & 0x0f ] );
            rv.push_back( hex[   c        & 0x0f ] );
        }
    }

    rv.append( "'" );

    return rv;
}

string
findFirstExisting( const StringList & paths )
{
    namespace fs = boost::filesystem;
    for ( const string & path : paths )
        if ( fs::exists( path ) )
            return path;
    return "";
}

// mandatory is "not optional"
const int CMD_MANDATORY = 0;

/**
 * Signal a system-level error.
 */

class OSError
    : public std::runtime_error
{
public:

    /**
     * Create a new OSError.
     *
     * The text is copied verbatim.  This constructor also consults
     * the value of 'errno' (which is thread-local on Linux), and puts
     * it all together to provide a human-readable output when what()
     * is called.
     *
     * @param[in] text any additional text to add to error message.
     */

    OSError( const char * text );

    /** Create a new OSError from a string */
    OSError( const string & text );

    // FIXME: is "errno" too unix-specific?

    /**
     * Retrieve the 'errno' value that triggered this exception.
     *
     * @return the original errno value.
     */

    int getErrno() const;

private:

    // original errno
    int m_iErrNo;

    static string genWhatString( const string & text );

}; // end class OSError

string
OSError::genWhatString( const string & text )
{
    std::ostringstream s;

    s << text << ": error " << errno;

    const int maxBufLen = 256;
    char buf[ maxBufLen ];
    s << " (" << strerror_r( errno, buf, maxBufLen ) << ")";

    return s.str();
}

OSError::OSError( const char * text )
    : std::runtime_error( genWhatString( text ) ),
      m_iErrNo( errno )
{
}

OSError::OSError( const string & text )
    : std::runtime_error( genWhatString( text ) ),
      m_iErrNo( errno )
{
}

int
OSError::getErrno() const
{
    return m_iErrNo;
}

} // end namespace [anonymous]

// =====================================================================

namespace OpenSSL
{

// ---------------------------------------------------------------------

Environment::Environment()
{
    DEBUG( "env: ctor: initializing OpenSSL" );
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    DEBUG( "env: ctor: done" );
}

Environment::~Environment()
{
    DEBUG( "env: dtor: shutting down OpenSSL" );
    EVP_cleanup();
    ENGINE_cleanup();

    DEBUG( "env: dtor: done" );
}

// ---------------------------------------------------------------------

Engine::Engine()
    : m_pEngine( 0 )
{
    DEBUG( "engine: ctor: done" );
}

/* virtual */
Engine::~Engine()
{
    if ( m_pEngine )
    {
        DEBUG( "engine: dtor: freeing " << m_pEngine );
        ENGINE_free( m_pEngine );
        m_pEngine = 0;
    }
    DEBUG( "engine: dtor: done" );
}

// ---------------------------------------------------------------------

CryptoDevEngine::CryptoDevEngine( int /* dummy */ )
{
    DEBUG( "cryptodev: ctor: loading and configuring" );
    ENGINE_load_cryptodev();

    ENGINE * cde = ENGINE_by_id( "cryptodev" );
    if ( ! cde )
        throw Exception( "cryptodev: load failed" );

    m_pEngine = cde;

    DEBUG( "cryptodev: ctor: initializing " << m_pEngine );
    if ( 1 != ENGINE_init( cde ) )
        throw Exception( "cryptodev: init failed" );

#if USE_CRYPTODEV_RSA
    DEBUG( "cryptodev: ctor: setting as rsa default" );
    if ( 1 != ENGINE_set_default_RSA( cde ) )
        throw Exception( "cryptodev: could not use for RSA" );
#endif // USE_CRYPTODEV_RSA

#if USE_CRYPTODEV_CIPHERS
    DEBUG( "cryptodev: ctor: setting as cipher default" );
    if ( 1 != ENGINE_set_default_ciphers( cde ) )
        throw Exception( "cryptodev: could not use for ciphers" );
#endif // USE_CRYPTODEV_CIPHERS
        
#if USE_CRYPTODEV_DIGESTS
    DEBUG( "cryptodev: ctor: setting as digest default" );
    if ( 1 != ENGINE_set_default_digests( cde ) )
        throw Exception( "cryptodev: could not use for digests" );
#endif // USE_CRYPTODEV_DIGESTS

    DEBUG( "cryptodev: ctor: done" );
}

/* virtual */
CryptoDevEngine::~CryptoDevEngine()
{
    DEBUG( "cryptodev: dtor: finishing " << m_pEngine );
    ENGINE_finish( m_pEngine );

    DEBUG( "cryptodev: dtor: done" );
}

// ---------------------------------------------------------------------

DynamicEngine::DynamicEngine( const string & id,
                              const StringList & engineLibPaths )
{
    DEBUG( "dynamic: ctor: loading and configuring dynamic engine" );
    ENGINE_load_dynamic();

    ENGINE * dyn = ENGINE_by_id( "dynamic" );
    if ( ! dyn )
        throw Exception( "dynamic: load failed" );

    m_pEngine = dyn;

    const string engineLibPath( findFirstExisting( engineLibPaths ) );
    if ( engineLibPath.empty() )
        throw Exception( "dynamic: unable to find engine lib path" );

    DEBUG( "dynamic: ctor: so_path=" << QS( engineLibPath ) );
    if ( 1 != ENGINE_ctrl_cmd_string( dyn, "SO_PATH", engineLibPath.c_str(), CMD_MANDATORY ) )
        throw Exception( "dynamic: setting so_path <= " + QS( engineLibPath ) );

    DEBUG( "dynamic: ctor: id=" << QS( id ) );
    if ( 1 != ENGINE_ctrl_cmd_string( dyn, "ID", id.c_str(), CMD_MANDATORY ) )
        throw Exception( "dynamic: setting id <= " + QS( id ) );

    DEBUG( "dynamic: ctor: list_add=1" );
    if ( 1 != ENGINE_ctrl_cmd( dyn, "LIST_ADD", 1, NULL, NULL, CMD_MANDATORY ) )
        throw Exception( "dynamic: setting list_add <= 1" );

    DEBUG( "dynamic: ctor: load=1" );
    if ( 1 != ENGINE_ctrl_cmd( dyn, "LOAD", 1, NULL, NULL, CMD_MANDATORY ) )
        throw Exception( "dynamic: setting load <= 1" );

    DEBUG( "dynamic: ctor: done" );
}

/* virtual */
DynamicEngine::~DynamicEngine()
{
    DEBUG( "dynamic: dtor: done" );
}

// ---------------------------------------------------------------------

TokenEngine::TokenEngine( const StringList & modulePaths )
{
    ENGINE * tok = ENGINE_by_id( "pkcs11" );
    if ( ! tok )
        throw Exception( "token: unable to get engine" );

    m_pEngine = tok;

    const string modulePath( findFirstExisting( modulePaths ) );
    if ( modulePath.empty() )
        throw Exception( "token: unable to find module path" );

    DEBUG( "token: ctor: module_path=" << QS( modulePath ) );
    if ( 1 != ENGINE_ctrl_cmd_string( tok, "MODULE_PATH", modulePath.c_str(), CMD_MANDATORY ) )
        throw Exception( "token: setting module_path <= " + QS( modulePath ) );

    DEBUG( "token: ctor: initializing " << m_pEngine );
    if ( 1 != ENGINE_init( tok ) )
        throw Exception( "token: unable to initialize" );

    DEBUG( "token: ctor: done" );
}

/* virtual */
TokenEngine::~TokenEngine()
{
    DEBUG( "token: dtor: finishing " << m_pEngine );
    ENGINE_finish( m_pEngine );

    DEBUG( "token: dtor: done" );
}

void 
TokenEngine::login( const string & pin )
{
    if ( 1 != ENGINE_ctrl_cmd_string( m_pEngine, "PIN",
                                      pin.c_str(), CMD_MANDATORY ) )
        throw Exception( "token: unable to log in"
                               " with PIN=" + QS( pin ) );
}

TokenEngine::PKeyPtr
TokenEngine::getPrivKey( const string & label )
{
    const string keyId( "label_" + label );
    EVP_PKEY * pkey =
      ENGINE_load_private_key( m_pEngine, keyId.c_str(), NULL, NULL );
    DEBUG( "token: got pkey=" << pkey );
    if ( ! pkey )
        throw Exception( "token: unable to find private key"
                               " with label=" + QS( label ) );
    return PKeyPtr(
        pkey, 
        [=]( EVP_PKEY * p ){
            DEBUG( "gpk: releasing key " << keyId << " @" << p );
            ENGINE_ctrl_cmd( m_pEngine, "RELEASE_KEY", 0,
                             static_cast< void * >( p ), NULL, CMD_MANDATORY );
        } );
}

// ---------------------------------------------------------------------

namespace
{

string
getOpenSSLErrors( const string & what )
{
    std::unique_ptr< BIO, int (*)(BIO *) > mem( BIO_new( BIO_s_mem() ), &BIO_free );
    ERR_print_errors( mem.get() );
    char * begin = 0;

    // #define BIO_get_mem_data(b,pp) BIO_ctrl(b,BIO_CTRL_INFO,0,(char *)pp)
    // le sigh...
    // long bytes = BIO_get_mem_data( mem.get(), &begin );
    long bytes = BIO_ctrl( mem.get(), BIO_CTRL_INFO, 0, static_cast< char * * >( &begin ) );

    string rv( what );
    rv.append( ":\n" );
    rv.append( begin, bytes );

    return rv;
}

}

Exception::Exception( const string & what )
    : std::runtime_error( getOpenSSLErrors( what ) )
{
}

// ---------------------------------------------------------------------

File::File( const string & path, const string & mode )
    : m_pBIO( BIO_new_file( path.c_str(), mode.c_str() ) )
{
}

File::~File()
{
    BIO_free( m_pBIO );
}

// ---------------------------------------------------------------------

namespace
{

int boundedFileWrite( BIO * DEBUG_FINE_ONLY( bio ),
                      const char * /* buf */, int bufLen )
{
    DEBUG_FINE_ONLY( const BoundedFile * bf( static_cast< BoundedFile * >( bio->ptr ) ) );
    DEBUG_FINE( "bfw: path=" << QS( bf->getPath() ) << ", len=" << bufLen );
    return bufLen;
}

int boundedFileRead( BIO * bio, char * buf, int bufLen )
{
    BoundedFile * bf( static_cast< BoundedFile * >( bio->ptr ) );
    DEBUG_FINE( "bfr: path=" << QS( bf->getPath() ) << ", len=" << bufLen );
    return bf->read( buf, bufLen );
}

int boundedFilePutS( BIO * DEBUG_FINE_ONLY( bio ), const char * /* cp */ )
{
    DEBUG_FINE_ONLY( const BoundedFile * bf( static_cast< BoundedFile * >( bio->ptr ) ) );
    DEBUG_FINE( "bfps: path=" << QS( bf->getPath() ) );
    return 1;
}

int boundedFileGetS( BIO * bio, char * buf, int bufLen )
{
    BoundedFile * bf( static_cast< BoundedFile * >( bio->ptr ) );
    DEBUG_FINE( "bfgs: path=" << QS( bf->getPath() ) << ", len=" << bufLen );
    return bf->read( buf, bufLen );
}

long boundedFileCtrl( BIO * bio, int i, long l, void * p )
{
    const BoundedFile * bf( static_cast< BoundedFile * >( bio->ptr ) );
    DEBUG( "bfctrl: path=" << QS( bf->getPath() ) << ", "
                "i=" << i << ", l=" << l << ", p=" << p );
    return 1L;
}

int boundedFileCreate( BIO * /* bio */ )
{
    DEBUG_FINE( "bfcreate:" );
    return 1;
}

int boundedFileDestroy( BIO * /* bio */ )
{
    DEBUG_FINE( "bfdestroy:" );
    return 1;
}

BIO_METHOD boundedMethods =
{
    /* type          = */ BIO_TYPE_FILE,
    /* name          = */ "BoundedFile",
    /* bwrite        = */ &boundedFileWrite,
    /* bread         = */ &boundedFileRead,
    /* bputs         = */ &boundedFilePutS,
    /* bgets         = */ &boundedFileGetS,
    /* ctrl          = */ &boundedFileCtrl,
    /* create        = */ &boundedFileCreate,
    /* destroy       = */ &boundedFileDestroy,
    /* callback_ctrl = */ NULL
};

}

BoundedFile::BoundedFile( const string & path,
                          const int64_t end )
    : m_sPath( path ),
      m_iEnd( end ),
      m_file( open( path.c_str(), O_RDONLY ) ),
      m_pBIO( BIO_new( &boundedMethods ) )
{
    if ( m_file < 0 )
        throw OSError( "opening " + QS( path ) );
    DEBUG( "bf: ctor: path=" << QS( path ) << ", end=" << end );
    m_pBIO->ptr = this;
    m_pBIO->init = 1;
}

BoundedFile::~BoundedFile()
{
    BIO_free( m_pBIO );
    DEBUG( "bf: dtor: path=" << QS( m_sPath ) );
}

int
BoundedFile::read( char * buf, int bufLen )
{
    const off64_t cur( lseek64( m_file, 0, SEEK_CUR ) );
    if ( cur == static_cast< off64_t >( -1 ) )
        throw OSError( "finding current offset in " + QS( m_sPath ) );

    const size_t len( 
        static_cast< size_t >( 
            ( m_iEnd < cur + bufLen ) ? m_iEnd - cur : bufLen
        )
    );
    const int rv = static_cast< int >( ::read( m_file, buf, len ) );

    DEBUG_FINE( "bf-rd: " << QS( m_sPath ) << ": "
                "end=" << m_iEnd << ", cur=" << cur << ", "
                "len=" << len << ", rv=" << rv );
    return rv;
}

// ---------------------------------------------------------------------

} // end namespace OpenSSL
