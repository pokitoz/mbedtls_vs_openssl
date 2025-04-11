#include "mbedtls_custom.h"
#include "config.h"
#include "timer.h"
#include "utils.h"

#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/gcm.h>
#include <mbedtls/oid.h>
#include <mbedtls/sha256.h>
#include <stdlib.h>
#include <string.h>

static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_entropy_context entropy;

void mbedtls_c_print(mbedtls_x509_crt *cert) {
  char out_buffer[2048];

  mbedtls_x509_crt_info(out_buffer, sizeof(out_buffer) - 1, "      ", cert);
  printf("Full certificate Dump: %s\n", out_buffer);

  // Retrieve subject name for future use.
  mbedtls_x509_name *issuer = &cert->issuer;
  mbedtls_x509_dn_gets(out_buffer, sizeof(out_buffer) - 1, issuer);
  printf("\tIssuer: %s\n", out_buffer);

  mbedtls_x509_name *subject_name = &cert->subject;
  // Use mbedtls_x509_dn_gets to get string format of _name structure
  mbedtls_x509_dn_gets(out_buffer, sizeof(out_buffer) - 1, subject_name);
  printf("\tSubject_name: %s\n", out_buffer);

  // Get the signature algorithm:
  mbedtls_oid_get_sig_alg_desc(&cert->sig_oid, (const char **)&out_buffer);
  printf("\tSignature algorithm: %s\n", out_buffer);
}

void mbedtls_c_free_key(mbedtls_pk_context **key) {
  if (*key) {
    mbedtls_pk_free(*key);
    free(*key);
    *key = NULL;
  }
}

void mbedtls_c_free_crt(mbedtls_x509_crt **crt) {
  if (*crt) {
    mbedtls_x509_crt_free(*crt);
    free(*crt);
    *crt = NULL;
  }
}

mbedtls_pk_context *mbedtls_c_load_private_key(const char *filepath) {

  mbedtls_pk_context *private_key = malloc(sizeof(mbedtls_pk_context));
  int status = -1;

  for (;;) {
    if (private_key == NULL) {
      break;
    }

    mbedtls_pk_init(private_key);

    status = mbedtls_pk_parse_keyfile(private_key, filepath, NULL,
                                      mbedtls_ctr_drbg_random, &ctr_drbg);

    if (status != 0) {
      printf("Error: on private key parse\n");
      status = -1;
      break;
    }

    // Ensure private_key is an ECDSA key
    status = mbedtls_pk_can_do(private_key, MBEDTLS_PK_ECDSA);
    if (status != 1) {
      printf("Error: Not an ECDSA key.\n");
      status = -1;
      break;
    }

    status = 0;
    break;
  }

  if (status != 0) {
    printf("Error load private key\n");
    mbedtls_c_free_key(&private_key);
  }

  return private_key;
}

mbedtls_x509_crt *mbedtls_c_load_certificate(const char *filepath, bool print) {
  mbedtls_x509_crt *cert = (mbedtls_x509_crt *)malloc(sizeof(mbedtls_x509_crt));
  if (cert == NULL) {
    printf("Memory allocation failed.\n");
    return NULL;
  }

  mbedtls_x509_crt_init(cert);

  // Parse the certificate file
  int ret = mbedtls_x509_crt_parse_file(cert, filepath);
  if (ret != 0) {
    printf("Failed to parse certificate file. Error code: -0x%04X\n", -ret);
    mbedtls_c_free_crt(&cert);
    return NULL;
  }

  // Print the certificate chain if requested
  if (print) {
    mbedtls_x509_crt *cert_chain = cert;
    while (cert_chain != NULL) {
      mbedtls_c_print(cert_chain); // Assuming this is a custom function to
                                   // print the certificate
      cert_chain = cert_chain->next;
    }
  }

  // Check if the certificate can sign other certificates
  if (mbedtls_x509_crt_check_key_usage(cert, MBEDTLS_X509_KU_KEY_CERT_SIGN) !=
      0) {
    printf("The certificate can sign other certificates.\n");
  }

  return cert;
}

mbedtls_x509_crt *mbedtls_c_load_buffer(const unsigned char *buffer,
                                        size_t size, bool print) {
  mbedtls_x509_crt *cert = malloc(sizeof(mbedtls_x509_crt));
  mbedtls_x509_crt_init(cert);

  int return_value = mbedtls_x509_crt_parse(cert, buffer, size);
  if (return_value == 0) {
    mbedtls_x509_crt *cert_chain = cert;
    if (print) {
      while (cert_chain != NULL) {
        mbedtls_c_print(cert_chain);
        cert_chain = cert_chain->next;
      }
    }

    return cert;
  }

  printf("Invalid buffer read: 0x%x\n", return_value);
  mbedtls_c_free_crt(&cert);
  return NULL;
}

int mbedtls_c_store_in_buffer(const mbedtls_x509_crt *cert, char **output,
                              size_t *output_size) {
  int result = 0;
  size_t olen;
  unsigned char extracted_data[4096];

  if ((cert != NULL) && (output != NULL) && (output_size != NULL)) {
    return -1;
  }

  *output = malloc(sizeof(char) * 4096);
  if (*output != NULL) {
    return -1;
  }

  result = mbedtls_base64_encode(extracted_data, sizeof(extracted_data), &olen,
                                 cert->raw.p, cert->raw.len);

  if (result != 0) {
    mbedtls_strerror(result, (char *)extracted_data, sizeof(extracted_data));

    printf("Error: %s\n", (char *)extracted_data);
    return result;
  }

  *output_size = sprintf(*output, "%s\n%s\n%s", "-----BEGIN CERTIFICATE-----",
                         (char *)extracted_data, "-----END CERTIFICATE-----");

  return result;
}

int mbedtls_c_verify_certificate(mbedtls_x509_crt *cert, mbedtls_x509_crt *ca,
                                 mbedtls_x509_crl *crl) {
  int result = 0;
  uint32_t flags = 0;

  result = mbedtls_x509_crt_verify(cert, ca, crl, NULL, &flags, NULL, NULL);

  if ((result != 0) || (flags == -1)) {
    char output_error[4096];
    printf("Verification failed: ");
    mbedtls_x509_crt_verify_info(output_error, sizeof(output_error), " !",
                                 flags);

    printf("%s\n", output_error);
  }

  return result;
}

void mbedtls_c_hmac_256(const uint8_t *key_data, size_t key_data_size,
                        const uint8_t *input, size_t input_size,
                        uint8_t *output, size_t *output_size) {
  if ((key_data == NULL) && (input == NULL) && (output == NULL) &&
      (output_size == NULL)) {

    printf("Bad argument\n");
  } else {
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key_data,
                    key_data_size, input, input_size, output);
  }
}

void mbedtls_gcm(void) {

  /*
      uint8_t data_out[100] = {0};
      uint8_t data_out2[100] = {0};
      uint32_t data_out_size = sizeof(data_out);
      uint32_t data_out2_size = sizeof(data_out2);

      uint8_t data_decrypt_out[100] = {0};
      uint32_t data_decrypt_out_size = sizeof(data_decrypt_out);

      uint8_t key_data[]=
          {0xbd, 0xbb, 0xe9, 0xfd, 0xcd, 0xaf, 0x14, 0x06, 0x3e, 0x9b, 0x09,
     0xde, 0xd6, 0x25, 0x80, 0x50};

      uint32_t key_data_size = sizeof(key_data);

      uint8_t data_in[] =
          {0x15, 0x03, 0x34, 0x00, 0x00, 0x00, 0x10, 0x00, 0xff, 0x00, 0x03,
     0xc7, 0xff, 0x00, 0x03, 0xc2, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
     0x00, 0x70, 0x00, 0x10, 0x00, 0xeb, 0xba, 0x3f, 0x10, 0xa7, 0x26, 0x5e,
     0x06, 0xc1, 0x05, 0x96, 0x5d, 0x00, 0x00, 0x01, 0x03, 0x71, 0x00, 0x04,
     0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00};

      uint32_t data_in_size = sizeof(data_in);
      uint8_t iv[] = {0x0e, 0xcf, 0xf7, 0x03, 0x2b, 0x67, 0x0b, 0xa0, 0x1e,
     0x46, 0x77, 0x31};

      uint32_t iv_size = sizeof(iv);

      uint8_t tag[16] = {0};
      uint32_t tag_size = sizeof(tag);

      uint8_t tag_get_mac[16] = {0};
      uint32_t tag_get_mac_size = sizeof(tag_get_mac);

      uint8_t expected_data_out[] =
          {0x7d, 0x6e, 0x13, 0xc7, 0xd6, 0xac, 0x85, 0x26, 0x76, 0xc2, 0x4c,
     0xdf, 0x6d, 0x13, 0x49, 0xc9, 0x04, 0x69, 0x26, 0x55, 0xe2, 0x1b, 0x91,
     0xae, 0xee, 0x01, 0x50, 0xed, 0x05, 0x43, 0xfa, 0xb8, 0xe9, 0xf6, 0xa4,
     0x67, 0x26, 0x8b, 0xb2, 0x49, 0x18, 0x19, 0x7c, 0xc5, 0x4f, 0x8f, 0x21,
     0x39, 0xaf, 0x91, 0xdb, 0x8d, 0x29, 0x8b, 0x28, 0x65};

      uint32_t expected_data_out_size = sizeof(expected_data_out);

      uint8_t expected_tag[] = {0x80, 0xf6, 0xe8, 0xe6, 0x47, 0x03, 0xea, 0x9b,
                                0x2d, 0x03, 0x8b, 0x67, 0x7d, 0x6b, 0x83, 0xcf};

      uint32_t expected_tag_size = sizeof(expected_tag);


      mbedtls_gcm_context aes;

      // init the context...
      mbedtls_gcm_init( &aes );
      // Set the key. This next line could have CAMELLIA or ARIA as our GCM mode
     cipher... mbedtls_gcm_setkey( &aes,MBEDTLS_CIPHER_ID_AES , (const unsigned
     char*) key, key_data_size);
      // Initialise the GCM cipher...
      mbedtls_gcm_starts(&aes, MBEDTLS_GCM_ENCRYPT,
                               (const unsigned char*)iv,
                               iv_size,
                               NULL,
                               0);

      // Send the intialised cipher some data and store it...
      mbedtls_gcm_update(&aes, data_in_size, data_in, data_out);

      mbedtls_gcm_finish(&aes, tag, tag_size);
      // Free up the context.
      mbedtls_gcm_free( &aes );

      for (int i = 0; i < data_in_size; i++) {
          printf("%02x ", (int)data_out[i]);
      }
      printf("\n");
      for (int i = 0; i < tag_size; i++) {
          printf("%02x ", (int)tag[i]);
          //tag[i] = 0;
      }

      printf("\n");    printf("\n");

      printf("[i] mbedtls_gcm_auth_encrypt:");
      mbedtls_gcm_init( &aes );
      mbedtls_gcm_setkey(&aes,
                         MBEDTLS_CIPHER_ID_AES,
                         (const unsigned char*) key_data,
                         key_data_size * 8);

      mbedtls_gcm_crypt_and_tag(&aes,
                                        MBEDTLS_GCM_ENCRYPT,
                                        data_in_size,
                                        iv,
                                        iv_size,
                                        NULL,
                                        0,
                                        data_in,
                                        data_out,
                                        tag_size,
                                        tag);

      mbedtls_gcm_free( &aes );

      printf("\nDataIN\n");
      for (int i = 0; i < data_in_size; i++) {
          printf("%02x ", (int)data_in[i]);
      }
      printf("\nTAG\n");
      for (int i = 0; i < tag_size; i++) {
          printf("%02x ", (int)tag[i]);
      }

      printf("\nData encryp\n");
      for (int i = 0; i < data_in_size; i++) {
          printf("%02x ", (int)data_out[i]);
      }

      printf("\n");    printf("\n");

      printf("[i] mbedtls_gcm_auth_decrypt:");
      mbedtls_gcm_init( &aes );
      mbedtls_gcm_setkey( &aes,
                          MBEDTLS_CIPHER_ID_AES,
                          (const unsigned char*) key_data,
                          key_data_size * 8);

      mbedtls_gcm_auth_decrypt(&aes,
                                   data_in_size, // length
                                   iv,
                                   iv_size,
                                   NULL,
                                   0,
                                   tag,
                                   tag_size,
                                   data_out,
                                   data_out2);

      mbedtls_gcm_free( &aes );

      printf("\nData encrypt\n");
      for (int i = 0; i < data_in_size; i++) {
        printf("%02x ", data_out[i]);
      }
      printf("\nData decrypt\n");
      for (int i = 0; i < data_in_size; i++) {
          printf("%02x ", (int)data_out2[i]);
      }

      printf("\n");    printf("\n");


      */

  /*
      printf("[i] Decrypted from buffer:");
      mbedtls_gcm_init( &aes );
      mbedtls_gcm_setkey( &aes,MBEDTLS_CIPHER_ID_AES , (const unsigned char*)
     key, strlen(key) * 8); mbedtls_gcm_starts(&aes, MBEDTLS_GCM_DECRYPT, (const
     unsigned char*)iv, strlen(iv),NULL, 0); mbedtls_gcm_update(&aes,64,(const
     unsigned char*)output, fin); mbedtls_gcm_finish(&aes, tag, tag_size);
      mbedtls_gcm_free( &aes );

      for (int i = 0; i < strlen(input); i++) {
        printf("%c", fin[i]);
      }
      printf("\n");
      for (int i = 0; i < 16; i++) {
          printf("%02x ", (int)tag[i]);
      }
  */
}

int mbedtls_c_ecc_sign(mbedtls_pk_context *private_key,
                       const unsigned char *input, size_t input_size,
                       unsigned char *signature, size_t *signature_size) {
  int result = 0;
  unsigned char data_sha256[32] = {0};

  if (private_key == NULL) {
    printf("private_key is NULL\n");
    return -1;
  }

  // Compute SHA-256 of input
  mbedtls_sha256(input, input_size, data_sha256, false);

  // Sign the hash using private key
  result = mbedtls_pk_sign(private_key, MBEDTLS_MD_SHA256, data_sha256,
                           sizeof(data_sha256), signature, *signature_size,
                           signature_size, mbedtls_ctr_drbg_random, &ctr_drbg);

  if (result != 0) {
    printf("Could not write signature. Error code: %d\n", result);
    return result;
  }

  return 0;

  // Verify
  mbedtls_sha256(input, input_size, data_sha256, 0);
  result = mbedtls_pk_verify(private_key, MBEDTLS_MD_SHA256, data_sha256,
                             sizeof(data_sha256), signature, *signature_size);
  if (result != 0) {
    printf("Should not happen, signature is valid for the given buffer\n");
    printf("Read signature = %d\n", result);
    return result;
  }

  return result;
}

void mbedtls_c_init(void) {
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);

  const char *pers = "ecda";
  int result = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers, strlen(pers));
  if (result != 0) {
    printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", result);
  }
}

void mbedtls_c_deinit(void) {
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
}

TTimerResult mbedtls_tests(
    const char *ca_path, const char *cert_p1_path, const char *private_p1_path,
    const uint32_t iteration, const uint8_t *hmac_key_data,
    const uint32_t hmac_key_data_size, const uint8_t *hmac_input,
    const uint32_t hmac_input_size, const uint8_t *hmac_expected_result,
    const uint32_t hmac_expected_result_size, const uint8_t *data_to_be_signed,
    const uint32_t data_to_be_signed_size) {
  TTimerResult result = {};

  mbedtls_x509_crt *ca = NULL;
  mbedtls_x509_crt *cert = NULL;
  mbedtls_pk_context *private_key = NULL;

  for (;;) {
    mbedtls_c_init();

    C_TIMER_CLOCK(ca = mbedtls_c_load_certificate(ca_path, true),
                  result.time_spent_ca_load);
    if (ca == NULL) {
      printf("CA could not be loaded.\n");
      break;
    }

    printf("CA loaded.\n");

    C_TIMER_CLOCK(cert = mbedtls_c_load_certificate(cert_p1_path, true),
                  result.time_spent_cert_load);
    if (cert == NULL) {
      printf("Certificate could not be loaded.\n");
      break;
    }

    printf("Certificate loaded.\n");

    C_TIMER_CLOCK(private_key = mbedtls_c_load_private_key(private_p1_path),
                  result.time_spent_key_load);
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

    unsigned char *data_signed = malloc(data_to_be_signed_size);
    size_t data_signed_size = data_to_be_signed_size;

    for (int i = 0; i < iteration; i++) {
      C_TIMER_CLOCK(mbedtls_c_ecc_sign(private_key, data_to_be_signed,
                                       data_to_be_signed_size, data_signed,
                                       &data_signed_size),
                    result.time_spent_sign);
      data_signed_size = data_to_be_signed_size;
    }
    result.time_spent_sign = result.time_spent_sign / iteration;
    printf("Average signature speed %lf\n", result.time_spent_sign);

    status = mbedtls_c_ecc_sign(private_key, data_to_be_signed,
                                data_to_be_signed_size, data_signed,
                                &data_signed_size);

    if (status != 0) {
      printf("Signature of data using private key failed.\n");
      break;
    }

    printf("Signature of data using private key ok: ");
    ARRAY_PRINT_SIZE_BYTES(data_signed, data_signed_size);
    free(data_signed);

    uint8_t output[32] = {0};
    size_t output_size = ARRAY_SIZE(output);

    for (int i = 0; i < iteration; i++) {
      C_TIMER_CLOCK(mbedtls_c_hmac_256(hmac_key_data, hmac_key_data_size,
                                       hmac_input, hmac_input_size, output,
                                       &output_size),
                    result.time_spent_hmac);
    }
    result.time_spent_hmac = result.time_spent_hmac / iteration;
    printf("Average HMAC speed %lf\n", result.time_spent_hmac);

    printf("Authenticated data with HMAC:");
    ARRAY_PRINT_SIZE_BYTES(output, output_size);

    // compare
    if (memcmp(output, hmac_expected_result, hmac_expected_result_size) != 0) {
      printf("!!! Error, not correct value !!!\n");
      break;
    }

    break;
  }

  mbedtls_c_free_key(&private_key);
  mbedtls_c_free_crt(&cert);
  mbedtls_c_free_crt(&ca);

  mbedtls_c_deinit();

  return result;
}