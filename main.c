#include "mbedtls_custom.h"
#include "openssl_custom.h"
#include "utils.h"

#include <stdio.h>
#include <time.h>

#define C_MAIN_CA_PATH "certificates/maincacert.pem"
#define C_SIGNED_CERT_P1_PATH "certificates/p1signed.pem"
#define C_PRIVATE_KEY_P1_PATH "certificates/p1privkey.pem"

static const uint8_t hmac_key_data[32] = {
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};

static const uint8_t hmac_input[2048] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                         1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                         1, 1, 1, 1, 1, 1, 1, 1, 1};

static const uint8_t hmac_expected_result[] = {
    0x5e, 0xc3, 0x3a, 0x25, 0x98, 0xee, 0xfb, 0x65, 0xa0, 0x4d, 0x51,
    0x15, 0xee, 0x4c, 0x64, 0x13, 0xa2, 0xdd, 0x04, 0xed, 0x8a, 0x1d,
    0x62, 0x76, 0x9a, 0xa9, 0xe9, 0x60, 0xd3, 0xd2, 0x4c, 0xbc};

// Number of time we do the loop to time the execution.
const unsigned int iteration = 1000;

int main(void) {
  time_t current_time = time(NULL);
  srand((unsigned int)current_time);

  static unsigned char data_to_be_signed[2048];
  for (size_t i = 0; i < ARRAY_SIZE(data_to_be_signed); i++) {
    data_to_be_signed[i] = rand();
  }

  printf("===== OpenSSL =====\n");
  TTimerResult openssl_result = openssl_tests(
      C_MAIN_CA_PATH, C_SIGNED_CERT_P1_PATH, C_PRIVATE_KEY_P1_PATH, iteration,
      hmac_key_data, ARRAY_SIZE(hmac_key_data), hmac_input,
      ARRAY_SIZE(hmac_input), hmac_expected_result,
      ARRAY_SIZE(hmac_expected_result), data_to_be_signed,
      ARRAY_SIZE(data_to_be_signed));

  printf("===== mbedTLS =====\n");
  TTimerResult mbedtls_result = mbedtls_tests(
      C_MAIN_CA_PATH, C_SIGNED_CERT_P1_PATH, C_PRIVATE_KEY_P1_PATH, iteration,
      hmac_key_data, ARRAY_SIZE(hmac_key_data), hmac_input,
      ARRAY_SIZE(hmac_input), hmac_expected_result,
      ARRAY_SIZE(hmac_expected_result), data_to_be_signed,
      ARRAY_SIZE(data_to_be_signed));

  printf("===== Finish =====\n");
  printf("\n");

  printf("      \topenssl \t|\t mbedtls\n");
  printf("      \t======= \t|\t =======\n");
  printf("ca   | \t%lf \t|\t %lf\n", openssl_result.time_spent_ca_load,
         mbedtls_result.time_spent_ca_load);
  printf("cert | \t%lf \t|\t %lf\n", openssl_result.time_spent_cert_load,
         mbedtls_result.time_spent_cert_load);
  printf("key  | \t%lf \t|\t %lf\n", openssl_result.time_spent_key_load,
         mbedtls_result.time_spent_key_load);
  printf("sign | \t%lf \t|\t %lf\n", openssl_result.time_spent_sign,
         mbedtls_result.time_spent_sign);
  printf("hmac | \t%lf \t|\t %lf\n", openssl_result.time_spent_hmac,
         mbedtls_result.time_spent_hmac);
  return 0;
}
