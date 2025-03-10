# mbedtls_vs_openssl

Comparison between OpenSSL and mbedTLS

## Get mbedTLS

```bash
git clone https://github.com/ARMmbed/mbedtls.git -b v3.6.2 --recurse-submodule && \
  pushd mbedtls && \
  mkdir build && cd build && \
  CFLAGS="-I$PWD/../.. -DMBEDTLS_CONFIG_FILE='<$PWD/../../config.h>'" && \
  cmake -DENABLE_TESTING=Off -DENABLE_PROGRAMS=Off .. && \
  make -j4 && \
  popd
```

The resulting libraries will be under `mbedtls/build/library`:
- libmbedcrypto.a
- libmbedtls.a
- libmbedx509.a

And the `mbedtls/include` folder must be included.

Or use apt-get

```bash
sudo apt-get install libmbedtls10
sudo apt-get install libmbedcrypto1
/sbin/ldconfig -p | grep "mbed"
```


## Get OpenSSL

```bash
git clone https://github.com/openssl/openssl.git -b openssl-3.4.1 && \
  push openssl && \
  ./config && \
  make -j4 && \
  popd
```
The resulting libraries will be under `openssl`:
- libssl.a
- libcrypto.a

And the `openssl/include` folder must be included.

Or use apt-get `sudo apt-get install libssl-dev`

## Generate the files

The program reads certificates that must be generated as follow:
```bash
cd certificates
./generate_certificates.sh
```
