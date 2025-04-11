#pragma once

#include "timer.h"

#include <openssl/opensslv.h>
#include <openssl/x509.h>
#include <stdbool.h>
#include <stdint.h>

X509 *openssl_load_certificate(const char *cert_path);

uint8_t openssl_get_signature_algorithm(X509 *certificate,
                                        char *signature_algorithm);

X509_STORE *openssl_load_ca(const char *ca_path, uint8_t *there_are_crls,
                            char *ca_sn, char *ca_algo);

EVP_PKEY *openssl_load_private_key(X509 *certificate,
                                   const char *private_key_path,
                                   const char *password);

uint8_t openssl_verify_certificate(X509_STORE *store, X509 *cert,
                                   uint8_t there_are_crls);

X509 *openssl_load_buffer(const char *data, size_t size);

bool openssl_store_in_buffer(X509 *certificate, BUF_MEM **output);

bool openssl_sign_buffer_sha256(EVP_PKEY *private_key,
                                const unsigned char *data,
                                const size_t data_length,
                                unsigned char *signature, size_t *size);

bool openssl_verify_signature_sha256(X509 *certificate,
                                     const unsigned char *data,
                                     const size_t data_length,
                                     const unsigned char *signature,
                                     size_t size);

void openssl_hmac_256(const uint8_t *key_data, size_t key_data_size,
                      const uint8_t *input, size_t input_size, uint8_t *output,
                      size_t *output_size);

void openssl_print_sn(X509 *x);

TTimerResult openssl_tests(
    const char *ca_path, const char *cert_p1_path, const char *private_p1_path,
    const uint32_t iteration, const uint8_t *hmac_key_data,
    const uint32_t hmac_key_data_size, const uint8_t *hmac_input,
    const uint32_t hmac_input_size, const uint8_t *hmac_expected_result,
    const uint32_t hmac_expected_result_size, const uint8_t *data_to_be_signed,
    const uint32_t data_to_be_signed_size);
