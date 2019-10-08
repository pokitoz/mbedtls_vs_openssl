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

    if (ca!= NULL) {
    	printf("CA: there_are_crls %u. Subject: %s. Algo: %s\n",
    	       there_are_crls,
    	       ca_sn,
               ca_algo);
    }

    X509* cert = openssl_load_certificate("certificates/p1signed.pem");
	char signature_algorithm[128];
	openssl_get_signature_algorithm(cert, signature_algorithm);
	printf("Signature: %s\n", signature_algorithm);


    printf("===== Finish =====\n");
    return 0;
}
