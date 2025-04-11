
DEBUG := 0
# CFLAGS / LFLAGS
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

C_SRCS=\
	main.c \
	openssl_custom.c \
	mbedtls_custom.c

all: ${BINARY}
setup: setup_mbed setup_openssl setup_cert

setup_mbed: 
	cd mbedtls && \
	git submodule update --init --recursive && \
	mkdir -p build && \
	cd build && \
	CFLAGS="-I${PWD}/../../mbedconfig -DMBEDTLS_CONFIG_FILE='<${PWD}/../../mbedconfig/config.h>'" && \
	cmake -DENABLE_TESTING=Off -DENABLE_PROGRAMS=Off .. && \
	make -j4

setup_openssl:
	cd openssl && \
	./config && \
	make -j4

setup_cert:
	cd certificates && \
	./generate_certificates.sh

format:
	clang-format -style=llvm mbedtls_custom.* openssl_custom.* *.h main.c -i

${BINARY}: ${C_SRCS}
	gcc -I${MBEDTLS_INCLUDE} \
		-I${OPENSSL_INCLUDE} \
		-I./mbedconfig \
		${CFLAGS} \
		${C_SRCS} \
		-o $@ \
		${OPENSSL_LIBRARY} \
		${MBEDTLS_LIBRARY} \
		${LFLAGS}

clean:
	rm ${BINARY}

.PHONY: clean setup setup_mbed setup_openssl format cert all