#include "openssl_custom.h"
#include "mbedtls_custom.h"

#include <openssl/opensslv.h>

#include <stdio.h>

int main(void)
{
    OpenSSL_add_all_algorithms();

    const X509* cert = openssl_load_certificate("p1signed.pem");

    printf("===== Finish =====\n");
    return 0;
}
