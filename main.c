#include "mbedtls_custom.h"
#include "openssl_custom.h"

#include <stdio.h>
#include <time.h>

#define C_MAIN_CA_PATH "certificates/maincacert.pem"
#define C_SIGNED_CERT_P1_PATH "certificates/p1signed.pem"
#define C_PRIVATE_KEY_P1_PATH "certificates/p1privkey.pem"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define ARRAY_PRINT_SIZE_BYTES(x, s)                                           \
  {                                                                            \
    for (uint32_t i = 0; i < (s); i++) {                                       \
      printf("0x%02x ", x[i]);                                                 \
    }                                                                          \
    printf("\n");                                                              \
  }

#define ARRAY_PRINT_BYTES(x) ARRAY_PRINT_SIZE_BYTES(x, ARRAY_SIZE(x))

static unsigned char data_to_be_signed[2048];

static uint8_t hmac_key_data[32] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                                    11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                                    22, 23, 24, 25, 26, 27, 28, 29, 30, 31};

static uint8_t hmac_input[2048] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                   1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                   1, 1, 1, 1, 1, 1, 1, 1, 1};

static const uint8_t hmac_expected_result[] = {
    0x5e, 0xc3, 0x3a, 0x25, 0x98, 0xee, 0xfb, 0x65, 0xa0, 0x4d, 0x51,
    0x15, 0xee, 0x4c, 0x64, 0x13, 0xa2, 0xdd, 0x04, 0xed, 0x8a, 0x1d,
    0x62, 0x76, 0x9a, 0xa9, 0xe9, 0x60, 0xd3, 0xd2, 0x4c, 0xbc};
// Number of time we do the loop to time the execution.
const unsigned int iteration = 1000;

static void openssl_tests(void) {

  X509_STORE *ca = NULL;
  uint8_t ca_has_crls;
  char ca_sn[1024];
  char ca_algo[128];

  X509 *cert = NULL;
  char cert_aglo[128];

  EVP_PKEY *private_key = NULL;
  BUF_MEM *mem_cert = NULL;
  X509 *cert_from_buffer = NULL;
  double time_spent = 0;

  for (;;) {

    if (OpenSSL_add_all_algorithms() != 1) {
      printf("OpenSSL error\n");
      break;
    }

    ca = openssl_load_ca(C_MAIN_CA_PATH, &ca_has_crls, ca_sn, ca_algo);

    if (ca == NULL) {
      printf("Could not load CA.\n");
      break;
    }

    printf("CA: ca_has_crls %u. Subject: %s. Algo: %s\n", ca_has_crls, ca_sn,
           ca_algo);

    cert = openssl_load_certificate(C_SIGNED_CERT_P1_PATH);

    openssl_get_signature_algorithm(cert, cert_aglo);
    printf("Certificate Algo: %s\n", cert_aglo);

    private_key = openssl_load_private_key(cert, C_PRIVATE_KEY_P1_PATH, NULL);

    if (private_key == NULL) {
      printf("private_key is not initilized.\n");
      break;
    }

    printf("private_key is initialized.\n");

    mem_cert = BUF_MEM_new();
    bool store_result = openssl_store_in_buffer(cert, &mem_cert);
    if (!store_result) {
      printf("Could not store certificate to buffer.\n");
      break;
    }

    printf("Store to buffer ok.\n");

    cert_from_buffer = openssl_load_buffer(mem_cert->data, mem_cert->length);
    if (cert_from_buffer == NULL) {
      printf("Could not load certificate from buffer.\n");
      break;
    }

    printf("Buffer loaded to certificate.\n");

    uint8_t result_verify_cert =
        openssl_verify_certificate(ca, cert, ca_has_crls);

    printf("Result verification certificate: %x\n", result_verify_cert);

    unsigned char data_signed[ARRAY_SIZE(data_to_be_signed)];
    size_t size_data_signed = 0;

    for (int i = 0; i < iteration; i++) {
      clock_t begin = clock();
      openssl_sign_buffer_sha256(private_key, data_to_be_signed,
                                 ARRAY_SIZE(data_to_be_signed), data_signed,
                                 &size_data_signed);
      time_spent += (double)(clock() - begin) / CLOCKS_PER_SEC;
    }
    printf("Average signature speed %lf\n", time_spent / iteration);

    bool result_sign = openssl_sign_buffer_sha256(
        private_key, data_to_be_signed, ARRAY_SIZE(data_to_be_signed),
        data_signed, &size_data_signed);

    if (!result_sign) {
      printf("Signature of data using private key failed.\n");
      break;
    }

    printf("Signature of data using private key ok: ");
    ARRAY_PRINT_SIZE_BYTES(data_signed, size_data_signed);

    bool result_verify_data = openssl_verify_signature_sha256(
        cert, data_to_be_signed, ARRAY_SIZE(data_to_be_signed), data_signed,
        size_data_signed);

    if (!result_verify_data) {
      printf("Verification of data using public key failed.\n");
      break;
    }

    uint8_t output[32];
    size_t output_size = ARRAY_SIZE(output);

    time_spent = 0;
    for (int i = 0; i < iteration; i++) {
      clock_t begin = clock();
      openssl_hmac_256(hmac_key_data, ARRAY_SIZE(hmac_key_data), hmac_input,
                       ARRAY_SIZE(hmac_input), output, &output_size);
      time_spent += (double)(clock() - begin) / CLOCKS_PER_SEC;
      output_size = ARRAY_SIZE(output);
    }
    printf("Average HMAC speed %lf\n", time_spent / iteration);

    printf("Authenticated data with HMAC:");
    ARRAY_PRINT_SIZE_BYTES(output, output_size);

    // compare
    if (memcmp(output, hmac_expected_result,
               ARRAY_SIZE(hmac_expected_result)) != 0) {
      printf("!!! Error, not correct value !!!\n");
      break;
    }

    break;
  }
}

void mbedtls_tests(void) {
  mbedtls_x509_crt *ca = NULL;
  mbedtls_x509_crt *cert = NULL;
  mbedtls_pk_context *private_key = NULL;
  double time_spent = 0;

  for (;;) {
    mbedtls_c_init();

    ca = mbedtls_c_load_certificate(C_MAIN_CA_PATH, true);
    if (ca == NULL) {
      printf("CA could not be loaded.\n");
      break;
    }

    printf("CA loaded.\n");

    cert = mbedtls_c_load_certificate(C_SIGNED_CERT_P1_PATH, true);
    if (cert == NULL) {
      printf("Certificate could not be loaded.\n");
      break;
    }

    printf("Certificate loaded.\n");

    private_key = mbedtls_c_load_private_key(C_PRIVATE_KEY_P1_PATH);
    if (private_key == NULL) {
      printf("private_key is not initilazed.\n");
      break;
    }

    printf("private_key is initialized.\n");

    int status = mbedtls_c_verify_certificate(cert, ca, NULL);
    if (status != 0) {
      printf("Certificate could not be verified.\n");
      break;
    }

    printf("Certificate verified by CA.\n");

    unsigned char data_signed[ARRAY_SIZE(data_to_be_signed)];
    size_t data_signed_size = ARRAY_SIZE(data_signed);

    for (int i = 0; i < iteration; i++) {
      clock_t begin = clock();
      mbedtls_c_ecc_sign(private_key, data_to_be_signed,
                         ARRAY_SIZE(data_to_be_signed), data_signed,
                         &data_signed_size);

      time_spent += (double)(clock() - begin) / CLOCKS_PER_SEC;
      data_signed_size = ARRAY_SIZE(data_signed);
    }
    printf("Average signature speed %lf\n", time_spent / iteration);

    status = mbedtls_c_ecc_sign(private_key, data_to_be_signed,
                                ARRAY_SIZE(data_to_be_signed), data_signed,
                                &data_signed_size);

    if (status != 0) {
      printf("Signature of data using private key failed.\n");
      break;
    }

    printf("Signature of data using private key ok: ");
    ARRAY_PRINT_SIZE_BYTES(data_signed, data_signed_size);

    uint8_t output[32] = {0};
    size_t output_size = ARRAY_SIZE(output);

    time_spent = 0;
    for (int i = 0; i < iteration; i++) {
      clock_t begin = clock();
      mbedtls_c_hmac_256(hmac_key_data, ARRAY_SIZE(hmac_key_data), hmac_input,
                         ARRAY_SIZE(hmac_input), output, &output_size);
      time_spent += (double)(clock() - begin) / CLOCKS_PER_SEC;
    }
    printf("Average HMAC speed %lf\n", time_spent / iteration);

    printf("Authenticated data with HMAC:");
    ARRAY_PRINT_SIZE_BYTES(output, output_size);

    // compare
    if (memcmp(output, hmac_expected_result,
               ARRAY_SIZE(hmac_expected_result)) != 0) {
      printf("!!! Error, not correct value !!!\n");
      break;
    }

    break;
  }

  mbedtls_c_free_key(&private_key);
  mbedtls_c_free_crt(&cert);
  mbedtls_c_free_crt(&ca);

  mbedtls_c_deinit();
}

int main(void) {
  time_t current_time = time(NULL);
  srand((unsigned int)current_time);

  for (size_t i = 0; i < ARRAY_SIZE(data_to_be_signed); i++) {
    data_to_be_signed[i] = rand();
  }

  printf("===== OpenSSL =====\n");
  openssl_tests();
  printf("===== mbedTLS =====\n");
  mbedtls_tests();
  printf("===== Finish =====\n");
  return 0;
}
