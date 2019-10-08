#ifndef OPENSSL_CUSTOM_H
#define OPENSSL_CUSTOM_H

#include <openssl/x509.h>
#include <stdint.h>

X509* openssl_load_certificate(const char* cert_path);

uint8_t openssl_get_signature_algorithm(X509* certificate,
                                        char* signature_algorithm);

#endif /* OPENSSL_CUSTOM_H */
