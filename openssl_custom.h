#ifndef OPENSSL_CUSTOM_H
#define OPENSSL_CUSTOM_H

#include <openssl/x509.h>
#include <stdint.h>

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

#endif /* OPENSSL_CUSTOM_H */
