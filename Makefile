
DEBUG := 0
include option.mk

BINARY=main

MBEDTLS_FOLDER=$(shell pwd)/mbedtls
OPENSSL_FOLDER=$(shell pwd)/openssl

MBEDTLS_INCLUDE=${MBEDTLS_FOLDER}/include
MBEDTLS_LIBRARY=\
	${MBEDTLS_FOLDER}/build/library/libmbedtls.a \
    ${MBEDTLS_FOLDER}/build/library/libmbedx509.a \
	${MBEDTLS_FOLDER}/build/library/libmbedcrypto.a

OPENSSL_INCLUDE=${OPENSSL_FOLDER}/include
OPENSSL_LIBRARY=\
	${OPENSSL_FOLDER}/libssl.a \
	${OPENSSL_FOLDER}/libcrypto.a

C_SOURCE=\
	main.c \
	openssl_custom.c \
	openssl_custom.h \
	mbedtls_custom.c \
	mbedtls_custom.h

all: ${BINARY}

cert:
	cd certificates && ./generate_certificates.sh

format:
	clang-format -style=llvm mbedtls_custom.* openssl_custom.* main.c -i

${BINARY}: ${C_SOURCE}
	gcc -I${MBEDTLS_INCLUDE} \
		-I${OPENSSL_INCLUDE} \
		${CFLAGS} \
		${C_SOURCE} \
		-o $@ \
		${OPENSSL_LIBRARY} \
		${MBEDTLS_LIBRARY} \
		${LFLAGS}

clean:
	rm ${BINARY}
