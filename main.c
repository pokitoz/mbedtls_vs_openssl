#include "openssl_custom.h"
#include "mbedtls_custom.h"

#include <time.h>
#include <stdio.h>

#define C_MAIN_CA_PATH "certificates/maincacert.pem"
#define C_SIGNED_CERT_P1_PATH "certificates/p1signed.pem"
#define C_PRIVATE_KEY_P1_PATH "certificates/p1privkey.pem"

static unsigned char data_to_be_signed[1024];

static uint8_t hmac_key_data[32] = 
{
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31
};

static uint8_t hmac_input[32] = 
{
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
};

static void openssl_tests(void)
{
    OpenSSL_add_all_algorithms();

    X509_STORE* ca = NULL;
    uint8_t ca_has_crls;
    char ca_sn[1024];
    char ca_algo[128];

    X509* cert = NULL;
    char cert_aglo[128];

    EVP_PKEY* private_key = NULL;
    BUF_MEM* mem_cert = NULL;
    X509* cert_from_buffer = NULL;

    ca = openssl_load_ca(C_MAIN_CA_PATH, &ca_has_crls, ca_sn, ca_algo);

    if (ca != NULL) {
        printf("CA: ca_has_crls %u. Subject: %s. Algo: %s\n",
               ca_has_crls, ca_sn, ca_algo);
    } else {
        printf("Could not load CA.\n");
    }

    cert = openssl_load_certificate(C_SIGNED_CERT_P1_PATH);

    openssl_get_signature_algorithm(cert, cert_aglo);
    printf("Certificate Algo: %s\n", cert_aglo);

    private_key = openssl_load_private_key(cert, C_PRIVATE_KEY_P1_PATH, NULL);

    if (private_key != NULL) {
        printf("private_key is initialized.\n");
    } else {
        printf("private_key is not initilized.\n");
    }

    mem_cert = BUF_MEM_new();
    bool store_result = openssl_store_in_buffer(cert, &mem_cert);
    if (store_result) {
        printf("Store to buffer ok.\n");
    } else {
        printf("Could not store certificate to buffer.\n");
    }

    cert_from_buffer = openssl_load_buffer(mem_cert->data, mem_cert->length);
    if (cert_from_buffer != NULL) {
        printf("Buffer loaded to certificate.\n");
    } else {
        printf("Could not load certificate from buffer.\n");
    }

    uint8_t result_verify_cert = openssl_verify_certificate(ca,
                                                            cert,
                                                            ca_has_crls);

    printf("Result verification certificate: %x\n", result_verify_cert);

    unsigned char data_signed[128];
    size_t size_data_signed = sizeof(data_signed);
    bool result_sign = openssl_sign_buffer_sha256(private_key,
                                                  data_to_be_signed,
                                                  sizeof(data_to_be_signed),
                                                  data_signed,
                                                  &size_data_signed);

    if (result_sign) {
        printf("Signature of data using private key ok.\n");
    } else {
        printf("Signature of data using private key failed.\n");
    }

    bool result_verify_data =
         openssl_verify_signature_sha256(cert,
                                         data_to_be_signed,
                                         sizeof(data_to_be_signed),
                                         data_signed,
                                         size_data_signed);

    if (result_verify_data) {
        printf("Verification of data using public key ok.\n");
    } else {
        printf("Verification of data using public key failed.\n");
    }

    uint8_t output[32];
    size_t output_size = 32;

    openssl_hmac_256(hmac_key_data,
                     sizeof(hmac_key_data),
                     hmac_input,
                     sizeof(hmac_input),
                     output,
                     &output_size);

    printf("Authenticated data with HMAC:");
    for (uint32_t i = 0; i < output_size; i++) {
        printf("0x%x ", output[i]);
    }
    printf("\n");

}

void mbedtls_tests(void)
{
    mbedtls_x509_crt* ca = NULL;
    mbedtls_x509_crt* cert = NULL;
    mbedtls_pk_context* private_key = NULL;

    mbedtls_c_init();

    ca = mbedtls_c_load_certificate(C_MAIN_CA_PATH, false);
    if (ca != NULL) {
        printf("CA loaded.\n");
    } else {
        printf("CA could not be loaded.\n");
    }

    cert = mbedtls_c_load_certificate(C_SIGNED_CERT_P1_PATH, false);
    if (cert != NULL) {
        printf("Certificate loaded.\n");
    } else {
        printf("Certificate could not be loaded.\n");
    }

    private_key = mbedtls_c_load_private_key(C_PRIVATE_KEY_P1_PATH);
    if (private_key != NULL) {
        printf("private_key is initialized.\n");
    } else {
        printf("private_key is not initilized.\n");
    }

    int result_verify_cert = mbedtls_c_verify_certificate(cert, ca, NULL);
    if (result_verify_cert == 0) {
        printf("Certificate verified by CA.\n");
    } else {
        printf("Certificate could not be verified.\n");
    }

    unsigned char data_signed[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
    size_t data_signed_size = sizeof(data_signed);
    int result_sign = mbedtls_c_ecc_sign(private_key,
                                         data_to_be_signed,
                                         sizeof(data_to_be_signed),
                                         data_signed,
                                         &data_signed_size);

    if (result_sign == 0)
    {
        printf("Signature of data using private key ok: ");

        for (uint32_t i = 0; i < data_signed_size; i++)
        {
            printf("0x%x ", data_signed[i]);
        }
        printf("\n");

    }
    else
    {
        printf("Signature of data using private key failed.\n");
    }


    uint8_t output[32];
    size_t output_size = 32;

    mbedtls_c_hmac_256(hmac_key_data,
                       sizeof(hmac_key_data),
                       hmac_input,
                       sizeof(hmac_input),
                       output,
                       &output_size);

    printf("Authenticated data with HMAC:");
    for (uint32_t i = 0; i < output_size; i++)
    {
        printf("0x%x ", output[i]);
    }
    printf("\n");


    mbedtls_c_deinit();
}

int main(void)
{
    // Randomize data
    time_t current_time = time(NULL);
    srand((unsigned int) current_time);

    for (size_t i = 0; i < sizeof(data_to_be_signed); i++)
    {
        data_to_be_signed[i] = rand();
    }

    printf("===== OpenSSL =====\n");
    openssl_tests();
    printf("===== mbedTLS =====\n");
    mbedtls_tests();
    printf("===== Finish =====\n");
    return 0;
}
