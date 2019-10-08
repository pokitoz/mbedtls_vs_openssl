#ifndef OPENSSL_CUSTOM_H
#define OPENSSL_CUSTOM_H

#include <openssl/x509.h>
#include <stdint.h>
#include <stdbool.h>

X509* openssl_load_certificate(const char* cert_path);

uint8_t openssl_get_signature_algorithm(X509* certificate,
                                        char* signature_algorithm);

X509_STORE* openssl_load_ca(const char* ca_path,
                            uint8_t* there_are_crls,
                            char* ca_sn,
                            char* ca_algo);

uint8_t openssl_verify_certificate(X509_STORE* store,
                                   X509* cert,
                                   uint8_t there_are_crls);

EVP_PKEY* openssl_load_private_key(X509* certificate,
                                   const char* private_key_path,
                                   const char* password);

X509* openssl_load_buffer(const char* data, size_t size);

bool openssl_store_in_buffer(X509* certificate, BUF_MEM** output);

bool openssl_sign_buffer_sha256(EVP_PKEY* private_key,
                                const unsigned char* data,
                                const size_t data_length,
                                unsigned char* signature,
                                size_t* size);

bool openssl_verify_signature_sha256(X509* certificate,
                                     const unsigned char* data,
                                     const size_t data_length,
                                     const unsigned char* signature,
                                     size_t size);

void openssl_hmac_256(void);

#endif /* OPENSSL_CUSTOM_H */
