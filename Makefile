BINARY=main

MBEDTLS_FOLDER=$(shell pwd)/mbedtls
OPENSSL_FOLDER=$(shell pwd)/openssl

MBEDTLS_INCLUDE=${MBEDTLS_FOLDER}/include
MBEDTLS_LIBRARY=\
	${MBEDTLS_FOLDER}/library/libmbedtls.a \
    ${MBEDTLS_FOLDER}/library/libmbedx509.a \
	${MBEDTLS_FOLDER}/library/libmbedcrypto.a

OPENSSL_INCLUDE=${OPENSSL_FOLDER}/include
OPENSSL_LIBRARY=\
	${OPENSSL_FOLDER}/libssl.a \
	${OPENSSL_FOLDER}/libcrypto.a

CFLAGS=\
	-Wall \
	-g3 \
	-std=c99

LFLAGS=\
	-ldl \
	-lz

C_SOURCE=\
	main.c \
	openssl_custom.c \
	mbedtls_custom.c

${BINARY}: ${C_SOURCE}
	gcc -I${MBEDTLS_INCLUDE} \
		-I${OPENSSL_INCLUDE} \
		${CFLAGS} \
		${C_SOURCE} \
		-o $@ \
		${OPENSSL_LIBRARY} \
		${LFLAGS}

clean:
	rm ${BINARY}
