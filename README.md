# mbedtls_vs_openssl

Comparison between OpenSSL and mbedTLS

## Get mbedTLS

```bash
# Tag used v3.6.2
make setup_mbed
```

The resulting libraries will be under `mbedtls/build/library`:
- libmbedcrypto.a
- libmbedtls.a
- libmbedx509.a

And the `mbedtls/include` folder must be included.

Or use apt-get as follow:

```bash
sudo apt-get install libmbedtls10
sudo apt-get install libmbedcrypto1
/sbin/ldconfig -p | grep "mbed"
```

## Get OpenSSL

```bash
# Tag used openssl-3.4.1
make setup_openssl
```
The resulting libraries will be under `openssl`:
- libssl.a
- libcrypto.a

And the `openssl/include` folder must be included.

Or use apt-get `sudo apt-get install libssl-dev`

## Generate the files

The program reads certificates that must be generated as follow:
```bash
make setup_cert
```

## Update format of file

Clang-format is used as follow:
```bash
make format
```

You might need to get the package `sudo apt install clang-format`