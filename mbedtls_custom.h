#ifndef MBEDTLS_CUSTOM_H
#define MBEDTLS_CUSTOM_H

#include <mbedtls/pk.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <stdbool.h>
#include <stdint.h>

void mbedtls_c_print(mbedtls_x509_crt *cert);

mbedtls_pk_context *mbedtls_c_load_private_key(const char *filepath);

mbedtls_x509_crt *mbedtls_c_load_certificate(const char *filepath, bool print);

mbedtls_x509_crt *mbedtls_c_load_buffer(const unsigned char *buffer,
                                        size_t size, bool print);

int mbedtls_c_store_in_buffer(const mbedtls_x509_crt *cert, char **output,
                              size_t *output_size);

int mbedtls_c_verify_certificate(mbedtls_x509_crt *cert, mbedtls_x509_crt *ca,
                                 mbedtls_x509_crl *crl);

void mbedtls_c_hmac_256(uint8_t *key_data, size_t key_data_size, uint8_t *input,
                        size_t input_size, uint8_t *output,
                        size_t *output_size);

void mbedtls_gcm(void);

int mbedtls_c_ecc_sign(mbedtls_pk_context *private_key, unsigned char *input,
                       size_t input_size, unsigned char *signature,
                       size_t *signature_size);

void mbedtls_c_init(void);
void mbedtls_c_deinit(void);
void mbedtls_c_free_crt(mbedtls_x509_crt **crt);
void mbedtls_c_free_key(mbedtls_pk_context **key);

#endif /* MBEDTLS_CUSTOM_H */
