#include "openssl_custom.h"
#include "mbedtls_custom.h"

#include <openssl/opensslv.h>
#include <stdio.h>

int main(void)
{
    OpenSSL_add_all_algorithms();

    uint8_t there_are_crls;
    char ca_sn[1024];
    char ca_algo[128];

    X509_STORE* ca = openssl_load_ca("certificates/maincacert.pem",
                                     &there_are_crls,
                                     ca_sn,
                                     ca_algo);

    if (ca != NULL) {
    	printf("CA: there_are_crls %u. Subject: %s. Algo: %s\n",
    	       there_are_crls,
    	       ca_sn,
               ca_algo);
    }

    X509* cert = openssl_load_certificate("certificates/p1signed.pem");
	char signature_algorithm[128];
	openssl_get_signature_algorithm(cert, signature_algorithm);
	printf("Signature: %s\n", signature_algorithm);

    EVP_PKEY* private_key =
        openssl_load_private_key(cert,
                                 "certificates/p1privkey.pem",
                                 NULL);

    if (private_key != NULL) {
        printf("private_key is initialized.\n");
    } else {
        printf("private_key is not initilized.\n");
    }

    BUF_MEM* mem = BUF_MEM_new();
    bool store_result = openssl_store_in_buffer(cert, &mem);
    if (store_result) {
        printf("Store to buffer ok.\n");
    } else {
        printf("Could not store certificate to buffer.\n");
    }

    X509* buffer_open_cert = openssl_load_buffer(mem->data, mem->length);
    if (buffer_open_cert != NULL) {
        printf("Buffer loaded to certificate.\n");
    } else {
        printf("Could not load certificate from buffer.\n");
    }


    uint8_t verify_result = openssl_verify_certificate(ca,
                                                       cert,
                                                       there_are_crls);

    printf("Result verification certificate: %x\n", verify_result);

    unsigned char data[1024];
    unsigned char data_signed[128];
    size_t size_data_signed = sizeof(data_signed);
    bool result_sign = openssl_sign_buffer_sha256(private_key,
	                                              data,
	                                              sizeof(data),
	                                              data_signed,
	                                              &size_data_signed);

    if (result_sign) {
        printf("Signature of data ok.\n");
    } else {
        printf("Signature failed.\n");
    }

    bool result_verify_data = openssl_verify_signature_sha256(cert,
                                                              data,
                                                              sizeof(data),
                                                              data_signed,
                                                              size_data_signed);

    if (result_verify_data) {
        printf("Verification of data ok.\n");
    } else {
        printf("Verification failed.\n");
    }

    openssl_hmac_256();

    printf("===== Finish =====\n");
    return 0;
}
