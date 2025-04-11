#pragma once

#include "timer.h"

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

void mbedtls_c_hmac_256(const uint8_t *key_data, size_t key_data_size,
                        const uint8_t *input, size_t input_size,
                        uint8_t *output, size_t *output_size);

void mbedtls_gcm(void);

int mbedtls_c_ecc_sign(mbedtls_pk_context *private_key,
                       const unsigned char *input, size_t input_size,
                       unsigned char *signature, size_t *signature_size);

void mbedtls_c_init(void);
void mbedtls_c_deinit(void);
void mbedtls_c_free_crt(mbedtls_x509_crt **crt);
void mbedtls_c_free_key(mbedtls_pk_context **key);

TTimerResult mbedtls_tests(
    const char *ca_path, const char *cert_p1_path, const char *private_p1_path,
    const uint32_t iteration, const uint8_t *hmac_key_data,
    const uint32_t hmac_key_data_size, const uint8_t *hmac_input,
    const uint32_t hmac_input_size, const uint8_t *hmac_expected_result,
    const uint32_t hmac_expected_result_size, const uint8_t *data_to_be_signed,
    const uint32_t data_to_be_signed_size);
