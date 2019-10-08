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

X509_STORE* openssl_load_ca(const char* ca_path,
                            uint8_t* there_are_crls,
                            char* ca_sn,
                            char* ca_algo)
{
    X509_STORE* store = X509_STORE_new();

	if ((ca_path == NULL) ||
	    (there_are_crls == NULL) ||
        (ca_sn == NULL) ||
        (ca_algo == NULL)) {

		return NULL;
	}

    *there_are_crls = 0;

    if (store != NULL) {
        BIO* bio = BIO_new(BIO_s_file());

        if (bio != NULL) {
            if (BIO_read_filename(bio, ca_path) > 0) {
                STACK_OF(X509_INFO)* info = PEM_X509_INFO_read_bio(bio,
                                                                   NULL,
                                                                   NULL,
                                                                   NULL);

                if (info != NULL) {
                    bool found_certificate = false;

                    for (int i = 0; i < sk_X509_INFO_num(info); i++) {
                        X509_INFO* itmp = sk_X509_INFO_value(info, i);

                        if (itmp->x509) {
                            // Retrieve subject name
                            if (ca_sn != NULL) {
                                X509_NAME* ca_sn_struct =
                                    X509_get_subject_name(itmp->x509);

                                if (ca_sn_struct != NULL) {
                                    char* ca_sn_str =
                                        X509_NAME_oneline(ca_sn_struct, 0, 0);

                                    if (ca_sn_str != NULL) {
                                        strncpy(ca_sn,
                                                ca_sn_str,
                                                strlen(ca_sn_str) + 1);

                                        OPENSSL_free(ca_sn_str);
                                    }
                                }
                            }

                            // Retrieve signature algorithm
                            if (ca_algo != NULL) {
                                if (openssl_get_signature_algorithm(itmp->x509, ca_algo) != 0) {
                                    printf("ca_algo: %s\n", ca_algo);
                                } else {
                                    printf("Could not get ca_algo\n");
                                }
                            }

                            X509_STORE_add_cert(store, itmp->x509);
                            found_certificate = true;
                        }

                        if (itmp->crl) {
                            X509_STORE_add_crl(store, itmp->crl);
                            *there_are_crls = 1;
                        }
                    }

                    sk_X509_INFO_pop_free(info, X509_INFO_free);
                    // At least one certificate was found !
                    if (found_certificate) {
                        BIO_free(bio);
                        return store;
                    }
                }
            }
            BIO_free(bio);
        }

        X509_STORE_free(store);
    }

    return NULL;
}

uint8_t openssl_verify_certificate(X509_STORE* store,
                                   X509* cert,
                                   uint8_t there_are_crls)
{
    uint8_t result = 0;

    if ((store == NULL) || (cert == NULL)) {
        return 1;
    }

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    if (ctx == NULL) {
        return 2;
    }

    //unsigned long flags = there_are_crls ? X509_V_FLAG_CRL_CHECK : 0;
    //flags |= X509_V_FLAG_X509_STRICT;
    //            | X509_V_FLAG_CHECK_SS_SIGNATURE
    //            | X509_V_FLAG_POLICY_CHECK;
   
    //printf("Flags: 0x%lx\n", flags);
    
    if(X509_STORE_CTX_init(ctx, store, cert, NULL) > 0) {
        //X509_STORE_CTX_set_flags(ctx, flags); 

        if(X509_verify_cert(ctx) > 0) {
            result = 0;
        } else {
            if (ctx->error == X509_V_OK) {
                printf("Invalidation error of certificate. No error code.\n");
            } else {
                printf("Invalidation error of certificate #%d: %s\n", 
                        ctx->error, X509_verify_cert_error_string(ctx->error));
            }
        }

        X509_STORE_CTX_cleanup(ctx);
    } else {
        printf("Cannot init context for verifying certificate\n");
    }

    X509_STORE_CTX_free(ctx);

    return result;
}

EVP_PKEY* openssl_load_private_key(X509* certificate,
                                   const char* private_key_path,
                                   const char* password)
{
    EVP_PKEY* private_key = NULL;

    BIO* bio = BIO_new(BIO_s_file());

    if(bio != NULL) {
        if(BIO_read_filename(bio, private_key_path) > 0) {
            private_key = PEM_read_bio_PrivateKey(bio,
                                                  NULL, 
                                                  NULL,
                                                  (void*) password);

            // Verify private key.
            if((private_key != NULL) &&
               (!X509_check_private_key(certificate, private_key))) {
            
                EVP_PKEY_free(private_key);
                private_key = NULL;
            }
        }

        BIO_free(bio);
    }

    return private_key;
}

X509* openssl_load_buffer(const char* data, size_t size)
{
    X509* certificate = NULL;
    BIO* cid = BIO_new_mem_buf(data, size);

    if(cid != NULL) {
        certificate = PEM_read_bio_X509_AUX(cid, NULL, NULL, NULL);
        BIO_free(cid);
    }

    return certificate;
}

bool openssl_store_in_buffer(X509* certificate, BUF_MEM** output)
{
    bool success = false;
    BIO *bio = BIO_new(BIO_s_mem());

    if ((bio != NULL) && (output != NULL) && (certificate != NULL)) {
        if (PEM_write_bio_X509(bio, certificate) > 0) {
            BIO_get_mem_ptr(bio, output);

            if (*output != NULL) {
                (void)BIO_set_close(bio, BIO_NOCLOSE);
                success = true;
            }

        } else {
            printf("Store in buffer failed.\n");
        }

        BIO_free(bio);
    }

    return success;
}

bool openssl_sign_buffer_sha256(EVP_PKEY* private_key,
                                const unsigned char* data,
                                const size_t data_length,
                                unsigned char* signature,
                                size_t* size)
{
    bool success = false;
    if ((private_key == NULL) &&
        (data == NULL) &&
        (signature != NULL) &&
        (size == NULL)) {

        return success;
    }

#if IS_OPENSSL_1_1
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
#else
    EVP_MD_CTX* ctx = (EVP_MD_CTX*)malloc(sizeof(EVP_MD_CTX));
#endif

    EVP_MD_CTX_init(ctx);
    EVP_PKEY_CTX* key;

    if (EVP_DigestSignInit(ctx, &key, EVP_sha256(), NULL, private_key) == 1) {
        if (EVP_DigestSignUpdate(ctx, data, data_length) == 1) {
            if ((EVP_DigestSignFinal(ctx, NULL, size) == 1) && (*size > 0)) {
                if (EVP_DigestSignFinal(ctx, signature, size) ==  1) {
                    success = true;
                }
            }
        }
    }

#if IS_OPENSSL_1_1
    EVP_MD_CTX_free(ctx);
#else
    EVP_MD_CTX_cleanup(ctx);
    free(ctx);
#endif

    return success;
}

bool openssl_verify_signature_sha256(X509* certificate,
                                     const unsigned char* data,
                                     const size_t data_length,
                                     const unsigned char* signature,
                                     size_t size)
{
    bool success = false;
    if ((certificate == NULL) && (data == NULL) && (signature != NULL)) {
        return success;
    }

#if IS_OPENSSL_1_1
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
#else
    EVP_MD_CTX* ctx = (EVP_MD_CTX*)malloc(sizeof(EVP_MD_CTX));
#endif

    EVP_MD_CTX_init(ctx);
    EVP_PKEY* public_key = X509_get_pubkey(certificate);

    if (public_key != NULL) {
        const EVP_MD * md = EVP_sha256();
        EVP_PKEY_CTX* key;
        int digest_init_result = EVP_DigestVerifyInit(ctx,
                                                      &key,
                                                      md,
                                                      NULL,
                                                      public_key);

        if (digest_init_result == 1) {
            int digest_update_result = EVP_DigestVerifyUpdate(ctx,
                                                              data,
                                                              data_length);

            if (digest_update_result == 1) {
                int digest_final_result = EVP_DigestVerifyFinal(ctx,
                                                                signature,
                                                                size);

                if (digest_final_result == 1) {
                    success = true;
                }
            }
        }
        EVP_PKEY_free(public_key);
    }

#if IS_OPENSSL_1_1
    EVP_MD_CTX_free(ctx);
#else
    EVP_MD_CTX_cleanup(ctx);
    free(ctx);
#endif

    return success;
}

void openssl_hmac_256(void)
{
    uint8_t key_data[32] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
                            15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
                            28, 29, 30, 31};

    uint8_t input[32] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                         1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

    uint32_t input_size = sizeof(input);
    uint8_t output[32];
    size_t output_size;

    EVP_PKEY* key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC,
                                         NULL,
                                         key_data,
                                         sizeof(key_data));

#if IS_OPENSSL_1_1
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
#else
    EVP_MD_CTX* ctx = (EVP_MD_CTX*)malloc(sizeof(EVP_MD_CTX));
#endif

    EVP_MD_CTX_init(ctx);
    EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key);
    EVP_DigestSignUpdate(ctx, input, input_size);
    EVP_DigestSignFinal(ctx, NULL, &output_size);
    EVP_DigestSignFinal(ctx, output, &output_size);

    for (uint32_t i = 0; i < output_size; i++) {
        printf("0x%x ", output[i]);
    }
    printf("\n");

    EVP_PKEY_free(key);

#if IS_OPENSSL_1_1
    EVP_MD_CTX_free(ctx);
#else
    EVP_MD_CTX_cleanup(ctx);
    free(ctx);
#endif

}
