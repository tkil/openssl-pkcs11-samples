#include <stdio.h>

#include <openssl/cms.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

int
main( int argc, char * argv [] )
{
    enum
    {
        ARG_IN_DATA_FILE_IX          = 1,
        ARG_OUT_SIG_FILE_IX          = 2,
        ARG_KEY_FILE_IX              = 3,
        ARG_KEY_PASS_IX              = 4,
        ARG_KEY_CERT_FILE_IX         = 5,
        ARG_FIRST_EXTRA_CERT_FILE_IX = 6
    };

    int exit_code = 0;

    /* -------------------------------------------------------------- */
    /* initialization */

    exit_code = 1;

    SSL_load_error_strings();
    SSL_library_init();

    /* -------------------------------------------------------------- */
    /* command-line processing */

    exit_code = 2;

    if ( argc < 6 )
    {
        fprintf( stderr, "usage: %s IN_DATA_FILE OUT_SIG_FILE"
                 " KEY_FILE KEY_PASS KEY_CERT EXTRA_CERTS...\n", argv[0] );
        return 1;
    }

    BIO * in_data_file = BIO_new_file( argv[ ARG_IN_DATA_FILE_IX ], "rb" );
    if ( ! in_data_file )
    {
        perror( argv[ ARG_IN_DATA_FILE_IX ] );
        goto end;
    }

    BIO * out_sig_file = BIO_new_file( argv[ ARG_OUT_SIG_FILE_IX ], "wb" );
    if ( ! out_sig_file )
    {
        perror( argv[ ARG_OUT_SIG_FILE_IX ] );
        goto free_in_data_file;
    }

    BIO * key_file = BIO_new_file( argv[ ARG_KEY_FILE_IX ], "rb" );
    if ( ! key_file )
    {
        perror( argv[ ARG_KEY_FILE_IX ] );
        goto free_out_sig_file;
    }

    char * pw = argv[ ARG_KEY_PASS_IX ];
    /* fprintf( stderr, "pw='%s'\n", pw ); */

    BIO * key_cert_file = BIO_new_file( argv[ ARG_KEY_CERT_FILE_IX ], "rb" );
    if ( ! key_cert_file )
    {
        perror( argv[ ARG_KEY_CERT_FILE_IX ] );
        goto free_key_file;
    }

    BIO * * extra_cert_files = NULL;
    int num_extra_cert_files = argc - ARG_FIRST_EXTRA_CERT_FILE_IX;
    if ( num_extra_cert_files > 0 )
    {
        extra_cert_files = calloc( num_extra_cert_files, sizeof( BIO * ) );
        if ( ! extra_cert_files )
        {
            perror( "extra_cert_files" );
            goto free_key_cert_file;
        }

        for ( int i = 0; i < num_extra_cert_files; ++i )
        {
            extra_cert_files[i] =
              BIO_new_file( argv[ ARG_FIRST_EXTRA_CERT_FILE_IX + i ], "rb" );
            if ( ! extra_cert_files[i] )
            {
                perror( argv[ ARG_FIRST_EXTRA_CERT_FILE_IX + i ] );
                goto free_key_cert_file;
            }
        }
    }

    /* -------------------------------------------------------------- */
    /* processing */

    exit_code = 3;

#define FAIL( msg, dest )                      \
    do {                                       \
        fprintf( stderr, "error: " msg "\n" ); \
        goto dest;                             \
    } while ( 0 )

    EVP_PKEY * key = PEM_read_bio_PrivateKey( key_file, NULL, NULL, pw );
    if ( ! key )
        FAIL( "reading private key", free_extra_cert_files );

    X509 * key_cert = PEM_read_bio_X509( key_cert_file, NULL, NULL, NULL );
    if ( ! key_cert )
        FAIL( "reading signing cert", free_key );

    STACK_OF(X509) * extra_certs = NULL;
    if ( num_extra_cert_files > 0 )
    {
        int success = 1;

        extra_certs = sk_X509_new_null();
        if ( ! extra_certs )
            FAIL( "allocating stack for extra certs", free_key_cert );

        for ( int i = 0; i < num_extra_cert_files; ++i )
        {
            X509 * tmp = PEM_read_bio_X509( extra_cert_files[i],
                                            NULL, NULL, NULL );
            if ( ! tmp )
            {
                fprintf( stderr, "error reading '%s'\n",
                         argv[ ARG_FIRST_EXTRA_CERT_FILE_IX + i ] );
                success = 0;
                break;
            }

            if ( ! sk_X509_push( extra_certs, tmp ) )
            {
                fprintf( stderr, "error pushing '%s'\n",
                         argv[ ARG_FIRST_EXTRA_CERT_FILE_IX + i ] );
                success = 0;
                X509_free( tmp );
                break;
            }
        }

        if ( ! success )
            FAIL( "could not read extra certs", free_extra_certs );
    }

    CMS_ContentInfo * ci = CMS_sign( key_cert, key, extra_certs, in_data_file,
                                     CMS_DETACHED | CMS_BINARY );

    /* if ( 1 != PEM_write_bio_CMS( out_sig_file, ci ) )
           FAIL( "could not write signature in PEM", free_ci ); */

    if ( 1 != i2d_CMS_bio( out_sig_file, ci ) )
           FAIL( "could not write signature in DER", free_ci );

    /* -------------------------------------------------------------- */
    /* success */

    exit_code = 0;

    /* -------------------------------------------------------------- */
    /* cleanup */

free_ci:
    CMS_ContentInfo_free( ci );

free_extra_certs:
    sk_X509_pop_free( extra_certs, &X509_free );

free_key_cert:
    X509_free( key_cert );

free_key:
    EVP_PKEY_free( key );

free_extra_cert_files:
    for ( int i = 0; i < num_extra_cert_files; ++i )
        BIO_vfree( extra_cert_files[ i ] );
    free( extra_cert_files );

free_key_cert_file:
    BIO_vfree( key_cert_file );

free_key_file:
    BIO_vfree( key_file );

free_out_sig_file:
    BIO_vfree( out_sig_file );

free_in_data_file:
    BIO_vfree( in_data_file );

    ERR_print_errors_fp( stderr );

    ERR_remove_state( /* pid= */ 0 );
    ENGINE_cleanup();
    CONF_modules_unload( /* all= */ 1 );
    EVP_cleanup();
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();

end:
    return exit_code;
}
