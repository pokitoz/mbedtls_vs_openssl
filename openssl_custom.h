#ifndef OPENSSL_CUSTOM_H
#define OPENSSL_CUSTOM_H

#include <openssl/x509.h>

X509* openssl_load_certificate(const char* cert_path);

#endif /* OPENSSL_CUSTOM_H */
