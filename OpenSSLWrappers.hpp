#ifndef OPENSSLWRAPPERS_HPP
#define OPENSSLWRAPPERS_HPP 1

/**
 * @file OpenSSLWrappers.hpp
 *
 * @author Anthony Foiani <anthony@foiani.com>
 *
 * @copyright 2013
 *
 * @license Boost Public License v1.0
 */

// openssl headers
#include <openssl/bio.h>
#include <openssl/ossl_typ.h>

// standard C++ headers
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

// boost headers
#include <boost/noncopyable.hpp>

// =====================================================================

// these vary by arch and cpu.
#define USE_CRYPTODEV 0

#define USE_CRYPTODEV_CIPHERS 1
#define USE_CRYPTODEV_DIGESTS 0
#define USE_CRYPTODEV_RSA     0

// =====================================================================

namespace OpenSSL
{

using std::int64_t;

using std::string;

typedef std::vector< string > StringList;

// ---------------------------------------------------------------------

/**
 * Manage the OpenSSL startup/shutdown issues.
 *
 * Create one of these before you start doing any other OpenSSL stuff;
 * at the end of your program, let it go out of scope and it will
 * clean up the OpenSSL environment.
 */

class Environment
    : public boost::noncopyable
{

public:
    Environment();
    ~Environment();

};

// ---------------------------------------------------------------------

class Engine
    : public boost::noncopyable
{

public:

    Engine();
    virtual ~Engine();

protected:

    ENGINE * m_pEngine;

};

// ---------------------------------------------------------------------

class CryptoDevEngine
    : public Engine
{

public:

    // the "int" arg is just a dummy so that i can call "in_place"
    CryptoDevEngine( int );
    virtual ~CryptoDevEngine();

};

// ---------------------------------------------------------------------

class DynamicEngine
    : public Engine
{

public:

    DynamicEngine( const string & id,
                   const StringList & engineLibPaths );
    virtual ~DynamicEngine();

};

// ---------------------------------------------------------------------

class TokenEngine
    : public Engine
{

public:

    TokenEngine( const StringList & modulePaths );
    virtual ~TokenEngine();

    void login( const string & pin );

    typedef std::function< void ( EVP_PKEY * ) > PKeyDeleter;
    typedef std::unique_ptr< EVP_PKEY, PKeyDeleter > PKeyPtr;
    PKeyPtr getPrivKey( const string & label );
};

// ---------------------------------------------------------------------

struct Exception
    : public std::runtime_error
{
    Exception( const string & what );
};

// ---------------------------------------------------------------------

class File
{

public:

    File( const string & path, const string & mode );
    ~File();

    BIO * getBIOPtr() { return m_pBIO; }

private:

    BIO * m_pBIO;

};

// ---------------------------------------------------------------------

class BoundedFile
{

public:

    BoundedFile( const string & path,
                 const int64_t end );
    ~BoundedFile();

    string getPath() const { return m_sPath; }

    BIO * getBIOPtr() { return m_pBIO; }

    int read( char * buf, int bufLen );

private:

    const string m_sPath;
    const int64_t m_iEnd;

    int m_file;

    BIO * m_pBIO;

};

// ---------------------------------------------------------------------

#define MY_OPENSSL_STACK(TYPE) OpenSSL::Stack< TYPE, stack_st_ ## TYPE >

template < typename Type, typename StackType >
class Stack
{

public:

    Stack()
        : m_pStack( sk_new( 0 ) )
    {
    }

    virtual ~Stack()
    {
        sk_free( m_pStack );
    }

    void push( Type * ptr )
    {
        if ( 1 != sk_insert( m_pStack, static_cast< void * >( ptr ), -1 ) )
            throw Exception( "sk_insert" );
    }

    StackType * getStackOf()
    {
        return reinterpret_cast< StackType * >( m_pStack );
    }

protected:

    _STACK * m_pStack;

};

template < typename Type,
           typename StackType,
           typename Deleter = std::function< void( Type * ) > >
class OwnedStack
    : public Stack< Type, StackType >
{

public:

    OwnedStack( Deleter deleter )
        : m_deleter( deleter )
    {
    }

    virtual ~OwnedStack()
    {
        if ( this->m_pStack &&
             this->m_pStack->data )
            for ( int i = 0, end = this->m_pStack->num; i < end; ++i )
                m_deleter( reinterpret_cast< Type * >( this->m_pStack->data[i] ) );
    }

private:

    Deleter m_deleter;
};

// ---------------------------------------------------------------------

} // end namespace OpenSSL

#endif // OPENSSLWRAPPERS_HPP
