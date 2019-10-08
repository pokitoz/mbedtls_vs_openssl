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
    X509* buffer_open_cert = openssl_load_buffer(mem->data, mem->length);

    uint8_t verify_result = openssl_verify_certificate(ca,
                                                       cert,
                                                       there_are_crls);

    printf("Result verification: %x\n", verify_result);

    printf("===== Finish =====\n");
    return 0;
}
