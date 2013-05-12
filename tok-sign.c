/* Demo program for signing data using a hardware token.

 compile line (assuming all the crypto bits are in /opt/crypto):

    /usr/local/gcc/bin/gcc -o tok-sign tok-sign.c -g --std=gnu99 -Wall \
      -I /opt/crypto/include \
      -L/opt/crypto/lib -lssl -lcrypto -lrt -lp11
*/

#include <stdio.h>
#include <unistd.h>
#include <time.h>

#include <openssl/cms.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <libp11.h>

#define FAIL( msg, dest )                      \
    do {                                       \
        fprintf( stderr, "error: " msg "\n" ); \
        goto dest;                             \
    } while ( 0 )

static
void
print_time( const char * label )
{
    struct timespec ts;
    clock_gettime( CLOCK_MONOTONIC, &ts );

    fprintf( stderr, "+%8lld.%09ld: %s\n",
             (long long)ts.tv_sec, ts.tv_nsec, label );
}

int
main( int argc, char * argv [] )
{
    enum
    {
        ARG_IN_DATA_FILE_IX = 1,
        ARG_OUT_SIG_FILE_IX = 2,
        ARG_KEY_LABEL_IX    = 3,
        ARG_KEY_PIN_IX      = 4
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

    if ( argc != 5 )
    {
        fprintf( stderr, "usage: %s IN_DATA_FILE OUT_SIG_FILE"
                 " KEY_LABEL KEY_PIN\n", argv[0] );
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

    const char * key_label = argv[ ARG_KEY_LABEL_IX ];
    char * key_id = calloc( sizeof( char ), strlen( key_label ) + 7 );
    strcpy( key_id, "label_" );
    strcat( key_id, key_label );
    const char * key_pin   = argv[ ARG_KEY_PIN_IX ];

    /* -------------------------------------------------------------- */
    /* load dynamic modules / engines */

    exit_code = 3;

    /* mandatory is "not optional"... */
    const int CMD_MANDATORY = 0;

    ENGINE_load_dynamic();
    ENGINE * dyn = ENGINE_by_id( "dynamic" );
    if ( ! dyn )
        FAIL( "retrieving 'dynamic' engine", free_out_sig_file );

    // if ( 1 != ENGINE_init( dyn ) )
    //     FAIL( "dyn: initializing", free_dyn );

    char * engine_pkcs11_so = "/opt/crypto/lib/engines/engine_pkcs11.so";
    if ( 0 != access( engine_pkcs11_so, R_OK ) )
    {
        engine_pkcs11_so = "/lib/engines/engine_pkcs11.so";
        if ( 0 != access( engine_pkcs11_so, R_OK ) )
            FAIL( "finding 'engine_pkcs11.so'", free_dyn );
    }

    if ( 1 != ENGINE_ctrl_cmd_string( dyn, "SO_PATH", engine_pkcs11_so, CMD_MANDATORY ) )
        FAIL( "dyn: setting so_path <= 'engine_pkcs11.so'", free_dyn );

    if ( 1 != ENGINE_ctrl_cmd_string( dyn, "ID", "pkcs11", CMD_MANDATORY ) )
        FAIL( "dyn: setting id <= 'pkcs11'", free_dyn );

    if ( 1 != ENGINE_ctrl_cmd( dyn, "LIST_ADD", 1, NULL, NULL, CMD_MANDATORY ) )
        FAIL( "dyn: setting list_add <= 1", free_dyn );

    if ( 1 != ENGINE_ctrl_cmd( dyn, "LOAD", 1, NULL, NULL, CMD_MANDATORY ) )
        FAIL( "dyn: setting load <= 1", free_dyn );

    ENGINE * pkcs11 = ENGINE_by_id( "pkcs11" );
    if ( ! pkcs11 )
        FAIL( "pkcs11: unable to get engine", free_dyn );

    char * opensc_pkcs11_so = "/opt/crypto/lib/opensc-pkcs11.so";
    if ( 0 != access( opensc_pkcs11_so, R_OK ) )
    {
        opensc_pkcs11_so = "/lib/opensc-pkcs11.so";
        if ( 0 != access( opensc_pkcs11_so, R_OK ) )
            FAIL( "finding 'opensc-pkcs11.so'", free_pkcs11 );
    }

    if ( 1 != ENGINE_ctrl_cmd_string( pkcs11, "MODULE_PATH", opensc_pkcs11_so, CMD_MANDATORY ) )
        FAIL( "setting module_path <= 'opensc-pkcs11.so'", free_pkcs11 );

    if ( 1 != ENGINE_ctrl_cmd_string( pkcs11, "PIN", key_pin, CMD_MANDATORY ) )
        FAIL( "setting pin", free_pkcs11 );

    if ( 1 != ENGINE_init( pkcs11 ) )
        FAIL( "pkcs11: unable to initialize engine", free_pkcs11 );

    /* -------------------------------------------------------------- */
    /* reading from token */

    exit_code = 4;

    EVP_PKEY * key = ENGINE_load_private_key( pkcs11, key_id, NULL, NULL );
    if ( ! key )
        FAIL( "reading private key", free_pkcs11 );

    PKCS11_CTX * p11_ctx = PKCS11_CTX_new();
    if ( ! p11_ctx )
        FAIL( "opening pkcs11 context", free_key );

    if ( 0 != PKCS11_CTX_load( p11_ctx, opensc_pkcs11_so ) )
        FAIL( "unable to load module", free_p11_ctx );

    PKCS11_SLOT * p11_slots;
    unsigned int num_p11_slots;
    if ( 0 != PKCS11_enumerate_slots( p11_ctx, &p11_slots, &num_p11_slots ) )
        FAIL( "enumerating slots", free_p11_ctx_module );

    PKCS11_SLOT * p11_used_slot =
      PKCS11_find_token( p11_ctx, p11_slots, num_p11_slots );
    if ( ! p11_used_slot )
        FAIL( "finding token", free_p11_slots );

    PKCS11_CERT * p11_certs;
    unsigned int num_p11_certs;
    if ( 0 != PKCS11_enumerate_certs( p11_used_slot->token, &p11_certs, &num_p11_certs ) )
        FAIL( "enumerating certs", free_p11_slots );

    STACK_OF(X509) * extra_certs = sk_X509_new_null();
    if ( ! extra_certs )
        FAIL( "allocating extra certs", free_p11_slots );

    X509 * key_cert = NULL;
    for ( unsigned int i = 0; i < num_p11_certs; ++i )
    {
        PKCS11_CERT * p11_cert = p11_certs + i;

        if ( ! p11_cert->label )
            continue;

        // fprintf( stderr, "p11: got cert label='%s', x509=%p\n",
        //         p11_cert->label, p11_cert->x509 );

        if ( ! p11_cert->x509 )
        {
            fprintf( stderr, "p11: ... no x509, ignoring\n" );
            continue;
        }

        const char * label = p11_cert->label;
        const unsigned int label_len = strlen( label );

        if ( strcmp( label, key_label ) == 0 )
        {
            // fprintf( stderr, "p11: ... saving as signing cert\n" );
            key_cert = p11_cert->x509;
        }
        else if ( strncmp( label, "encrypt", 7 ) == 0 &&
                  label_len == 8 &&
                  '0' <= label[7] && label[7] <= '3' )
        {
            // fprintf( stderr, "p11: ... ignoring as encrypting cert\n" );
        }
        else
        {
            // fprintf( stderr, "p11: ... saving as extra cert\n" );
            if ( ! sk_X509_push( extra_certs, p11_cert->x509 ) )
                FAIL( "pushing extra cert", free_extra_certs );
        }
    }

    if ( ! key_cert )
        FAIL( "finding signing cert", free_extra_certs );

    /* -------------------------------------------------------------- */
    /* signing */

    exit_code = 5;

    print_time( "calling CMS_sign" );
    CMS_ContentInfo * ci = CMS_sign( key_cert, key, extra_certs, in_data_file,
                                     CMS_DETACHED | CMS_BINARY );
    if ( ! ci )
        FAIL( "could not create signing structure", free_extra_certs );

    /* if ( 1 != PEM_write_bio_CMS( out_sig_file, ci ) )
           FAIL( "could not write signature in PEM", free_ci ); */

    print_time( "calling i2d_CMS_bio" );
    if ( 1 != i2d_CMS_bio( out_sig_file, ci ) )
           FAIL( "could not write signature in DER", free_ci );

    print_time( "done" );

    /* -------------------------------------------------------------- */
    /* success */

    exit_code = 0;

    /* -------------------------------------------------------------- */
    /* cleanup */

free_ci:
    CMS_ContentInfo_free( ci );

free_extra_certs:
    /* these certs are actually "owned" by the libp11 code, and are
     * presumably freed with the slot or context. */
    sk_X509_free( extra_certs );

free_p11_slots:
    PKCS11_release_all_slots( p11_ctx, p11_slots, num_p11_slots );

free_p11_ctx_module:
    PKCS11_CTX_unload( p11_ctx );

free_p11_ctx:
    PKCS11_CTX_free( p11_ctx );

free_key:
    EVP_PKEY_free( key );

free_pkcs11:
    ENGINE_free( pkcs11 );

free_dyn:
    ENGINE_free( dyn );

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
