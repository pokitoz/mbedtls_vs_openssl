#include "openssl_custom.h"
#include "mbedtls_custom.h"

#include <openssl/opensslv.h>

#include <stdio.h>

int main(void)
{
    OpenSSL_add_all_algorithms();

    X509* cert = openssl_load_certificate("certificates/p1signed.pem");
	char signature_algorithm[128];
	openssl_get_signature_algorithm(cert, signature_algorithm);
	printf("Signature: %s\n", signature_algorithm);
    printf("===== Finish =====\n");
    return 0;
}
