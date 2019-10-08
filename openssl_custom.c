#include "openssl_custom.h"
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>

#include <stdbool.h>
#include <string.h>

X509* openssl_load_certificate(const char* cert_path)
{
    X509* return_cert = NULL;

    if (cert_path != NULL) {
        BIO* in = BIO_new(BIO_s_file());

        if (in != NULL) {
            if (BIO_read_filename(in, cert_path) > 0) {
                return_cert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
            }

            BIO_free(in);
        }
    }

    return return_cert;
}

uint8_t openssl_get_signature_algorithm(X509* certificate,
                                        char* signature_algorithm)
{
    uint8_t result = 0;
    BUF_MEM* mem = NULL;
    X509_ALGOR* algo_structure = NULL;

    BIO* bio = BIO_new(BIO_s_mem());

    if ((bio != NULL) && (certificate != NULL)) {
        X509_get0_signature(NULL, &algo_structure, certificate);

        if (algo_structure != NULL) {
            if (i2a_ASN1_OBJECT(bio, algo_structure->algorithm) > 0) {
                BIO_get_mem_ptr(bio, &mem);

                if (mem != NULL) {
                    // Make sure the signature algorithm is the one expected
                    if (strncmp(mem->data, "ecdsa-with-SHA256", mem->length) == 0) {
                        strncpy(signature_algorithm, mem->data, mem->length);
                        result = 1;
                    } else if (strncmp(mem->data, "sha256WithRSAEncryption", mem->length) == 0) {
                        strncpy(signature_algorithm, mem->data, mem->length);
                        result = 1;
                    } else if (strncmp(mem->data, "sha1WithRSAEncryption", mem->length) == 0) {
                        strncpy(signature_algorithm, mem->data, mem->length);
                        result = 1;
                    }
                }
            }
        }

        BIO_free(bio);
    }

    return result;
}
