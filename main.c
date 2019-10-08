#include "openssl_custom.h"
#include "mbedtls_custom.h"

#include <openssl/opensslv.h>
#include <stdio.h>

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

    ca = openssl_load_ca("certificates/maincacert.pem",
                         &ca_has_crls,
                         ca_sn,
                         ca_algo);

    if (ca != NULL) {
    	printf("CA: ca_has_crls %u. Subject: %s. Algo: %s\n",
    	       ca_has_crls,
    	       ca_sn,
               ca_algo);
    }

    cert = openssl_load_certificate("certificates/p1signed.pem");

	openssl_get_signature_algorithm(cert, cert_aglo);
	printf("Certificate Algo: %s\n", cert_aglo);

    private_key = openssl_load_private_key(cert,
                                           "certificates/p1privkey.pem",
                                           NULL);

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

    unsigned char data_to_be_signed[1024];
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

    uint8_t key_data[32] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
                            15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
                            28, 29, 30, 31};

    uint8_t input[32] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                         1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

    uint8_t output[32];
    size_t output_size = 32;

    openssl_hmac_256(key_data,
                     sizeof(key_data),
                     input,
                     sizeof(input),
                     output,
                     &output_size);

    printf("Authenticated data with HMAC:");
    for (uint32_t i = 0; i < output_size; i++) {
        printf("0x%x ", output[i]);
    }
    printf("\n");

}

int main(void)
{
    openssl_tests();
    printf("===== Finish =====\n");
    return 0;
}
