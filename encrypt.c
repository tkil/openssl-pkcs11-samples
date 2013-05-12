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
        ARG_OUT_ENC_FILE_IX          = 2,
        ARG_ENC_CERT_FILE_IX         = 3,
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

    if ( argc != 4 )
    {
        fprintf( stderr, "usage: %s IN_DATA_FILE OUT_ENC_FILE"
                 " ENC_CERT\n", argv[0] );
        goto end;
    }

    BIO * in_data_file = BIO_new_file( argv[ ARG_IN_DATA_FILE_IX ], "rb" );
    if ( ! in_data_file )
    {
        perror( argv[ ARG_IN_DATA_FILE_IX ] );
        goto end;
    }

    BIO * out_enc_file = BIO_new_file( argv[ ARG_OUT_ENC_FILE_IX ], "wb" );
    if ( ! out_enc_file )
    {
        perror( argv[ ARG_OUT_ENC_FILE_IX ] );
        goto free_in_data_file;
    }

    BIO * enc_cert_file = BIO_new_file( argv[ ARG_ENC_CERT_FILE_IX ], "rb" );
    if ( ! enc_cert_file )
    {
        perror( argv[ ARG_ENC_CERT_FILE_IX ] );
        goto free_out_enc_file;
    }

    /* -------------------------------------------------------------- */
    /* processing */

    exit_code = 3;

#define FAIL( msg, dest )                      \
    do {                                       \
        fprintf( stderr, "error: " msg "\n" ); \
        goto dest;                             \
    } while ( 0 )

    X509 * enc_cert = PEM_read_bio_X509( enc_cert_file, NULL, NULL, NULL );
    if ( ! enc_cert )
        FAIL( "reading signing cert", free_enc_cert_file );

    STACK_OF(X509) * enc_certs = sk_X509_new_null();
    if ( ! enc_certs )
        FAIL( "allocating stack for encoding certs", free_enc_certs );

    if ( ! sk_X509_push( enc_certs, enc_cert ) )
        FAIL( "pushing encoding cert onto stock", free_enc_certs );

    enc_cert = NULL;

    CMS_ContentInfo * ci = CMS_encrypt( enc_certs, NULL, EVP_aes_128_cbc(),
                                        CMS_STREAM | CMS_BINARY );
    if ( ! ci )
        FAIL( "setting up encryption file", free_enc_certs );

    if ( 1 != i2d_CMS_bio_stream( out_enc_file, ci, in_data_file,
                                  CMS_STREAM | CMS_BINARY ) )
        FAIL( "could not write encrypted DER", free_ci );

    /* -------------------------------------------------------------- */
    /* success */

    exit_code = 0;

    /* -------------------------------------------------------------- */
    /* cleanup */

free_ci:
    CMS_ContentInfo_free( ci );

free_enc_certs:
    sk_X509_pop_free( enc_certs, &X509_free );

free_enc_cert_file:
    BIO_vfree( enc_cert_file );

free_out_enc_file:
    BIO_vfree( out_enc_file );

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
