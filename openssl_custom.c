#include "openssl_custom.h"
#include <openssl/pem.h>

X509* openssl_load_certificate(const char* cert_path)
{
    X509* return_cert = NULL;

    if(cert_path != NULL) {
        BIO* in = BIO_new(BIO_s_file());

        if(in != NULL) {
            if(BIO_read_filename(in, cert_path) > 0) {
                return_cert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
            }

            BIO_free(in);
        }
    }

    return return_cert;
}
