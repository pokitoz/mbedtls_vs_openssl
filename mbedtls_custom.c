#include "config.h"
#include "mbedtls_custom.h"
#include <mbedtls/base64.h>
#include <mbedtls/error.h>
#include <stdlib.h>

void mbedtls_c_print_opcode(void)
{
    char output[4096];
    int test_code[] = {-15616,
                       -52,
                       0xffffd800,
                       0xffffde80,
                       0xffffd900,
                       0xffffffcc};

    for(int i = 0; i < sizeof(test_code) / sizeof(int); i++) {
        mbedtls_strerror(test_code[i], output, 4096);
        printf("%d == 0x%x : error value : %s\n", test_code[i],
                                                  test_code[i],
                                                  output);
    }

    int test_flags[] = {0x1c008};
    for(int i = 0; i < sizeof(test_flags) / sizeof(int); i++) {
        mbedtls_x509_crt_verify_info(output, 4096, NULL, test_flags[i]);
        printf("%d == 0x%x : error value : %s\n", test_flags[i],
                                                  test_flags[i],
                                                  output);
    }
}

void mbedtls_c_print(mbedtls_x509_crt* cert)
{
    char out_buffer[1024];

    mbedtls_x509_crt_info(out_buffer, sizeof(out_buffer) - 1, "      ", cert);
    printf("Full certificate Dump:%s\n", out_buffer);

    // Retrieve subject name for future use.
    mbedtls_x509_name* issuer = &cert->issuer;
    mbedtls_x509_dn_gets(out_buffer, sizeof(out_buffer) - 1, issuer);
    printf("Issuer: %s\n", out_buffer);

    mbedtls_x509_name* subject_name = &cert->subject;
    // Use mbedtls_x509_dn_gets to get string format of _name structure
    mbedtls_x509_dn_gets(out_buffer, sizeof(out_buffer) - 1, subject_name);
    printf("Subject_name: %s\n", out_buffer);

    // Get the signature algorithm:
    mbedtls_x509_buf* sig_oid = &cert->sig_oid;
    mbedtls_x509_sig_alg_gets(out_buffer,
                              sizeof(out_buffer) - 1 /* For \0 */,
                              sig_oid,
                              cert->sig_pk,
                              cert->sig_md,
                              cert->sig_opts );

    printf("Signature algorithm: %s\n", out_buffer);
}

mbedtls_pk_context* mbedtls_c_load_private_key(const char* filepath)
{
    mbedtls_pk_context* private_key = malloc(sizeof(mbedtls_pk_context));
    if (private_key == NULL) {
        return NULL;
    }

    mbedtls_pk_init(private_key);

    if (mbedtls_pk_parse_keyfile(private_key, filepath, NULL) == 0) {
        return private_key;
    }

    free(private_key);
    return NULL;
}

mbedtls_x509_crt* mbedtls_c_load_certificate(const char* filepath, bool print)
{
    mbedtls_x509_crt* cert = malloc(sizeof(mbedtls_x509_crt));
    mbedtls_x509_crt_init(cert);

    if (mbedtls_x509_crt_parse_file(cert, filepath) == 0) {
        mbedtls_x509_crt* cert_chain = cert;
        if (print) {
            while (cert_chain != NULL) {
                mbedtls_c_print(cert_chain);
                cert_chain = cert_chain->next;
            }
        }

        if (cert->key_usage & MBEDTLS_X509_KU_KEY_CERT_SIGN) {
             printf("The certificate can sign\n");
        }

        return cert;
    }

    free(cert);
    return NULL;
}

mbedtls_x509_crt* mbedtls_c_load_buffer(const unsigned char* buffer,
                                        size_t size,
                                        bool print)
{
    mbedtls_x509_crt* cert = malloc(sizeof(mbedtls_x509_crt));
    mbedtls_x509_crt_init(cert);

    int return_value = mbedtls_x509_crt_parse(cert, buffer, size);
    if (return_value == 0) {
        mbedtls_x509_crt* cert_chain = cert;
        if (print) {
            while (cert_chain != NULL) {
                mbedtls_c_print(cert_chain);
                cert_chain = cert_chain->next;
            }
        }

        return cert;
    }

    printf("Invalid buffer read: 0x%x\n", return_value);
    free(cert);
    return NULL;
}

int mbedtls_c_store_in_buffer(const mbedtls_x509_crt* cert,
                              char** output,
                              size_t* output_size)
{
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

    result = mbedtls_base64_encode(extracted_data,
                                   sizeof(extracted_data),
                                   &olen,
                                   cert->raw.p,
                                   cert->raw.len);

    if(result != 0) {
        mbedtls_strerror(result,
                         (char*) extracted_data,
                         sizeof(extracted_data));

        printf("Error: %s\n", (char*) extracted_data);
        return result;
    }

    *output_size = sprintf(*output,
                           "%s\n%s\n%s",
                           "-----BEGIN CERTIFICATE-----",
                           (char*) extracted_data,
                           "-----END CERTIFICATE-----");

    return result;
}

int mbedtls_c_verify_certificate(mbedtls_x509_crt* cert,
                                 mbedtls_x509_crt* ca,
                                 mbedtls_x509_crl* crl)
{
    int result = 0;
    uint32_t flags = 0;

    result = mbedtls_x509_crt_verify(cert,
                                     ca,
                                     crl,
                                     NULL,
                                     &flags,
                                     NULL,
                                     NULL);

    if((result != 0) || (flags != 0)) {
        char output_error[4096];
        printf("Verification failed: ");
        mbedtls_x509_crt_verify_info(output_error,
                                     sizeof(output_error),
                                     " !",
                                     flags);

        printf("%s\n", output_error);
  }

  return result;
}
