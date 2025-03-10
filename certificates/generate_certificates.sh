#!/bin/bash -e

TMP_FOLDER="`pwd`/tmp"

CONFIG_FOLDER="`pwd`/cnf_files"
APPLICATION_CONFIG="${CONFIG_FOLDER}/appconf.cnf"
CA_CONFIG="${CONFIG_FOLDER}/maincaconf.cnf"

generate_ca_identity()
{
    local NAME=$1
    local CONFIG=$2

    rm -rf $TMP_FOLDER
    mkdir -p $TMP_FOLDER
    cp $APPLICATION_CONFIG $TMP_FOLDER
    cp $CA_CONFIG $TMP_FOLDER

    pushd $TMP_FOLDER
    local ECPARAM_FILE="ecdsaparam_${NAME}"
    local KEYOUT="${NAME}key.pem"
    local CERTOUT="${NAME}cert.pem"

    openssl ecparam -name prime256v1 > ${ECPARAM_FILE}
    openssl req -nodes \
        -x509 \
        -days 3650 \
        -newkey ec:${ECPARAM_FILE} \
        -keyout ${KEYOUT} \
        -out ${CERTOUT} \
        -config ${CONFIG}

    touch index.txt

    popd

    # Copy the CA certificate out
    cp $TMP_FOLDER/${CERTOUT} ./
}

sign_certificate()
{
    local NAME_CSR=$1
	local NAME_OUTPUT=$2
    local CONFIG=$3

    pushd $TMP_FOLDER

    # Ask CA to sign Certificate Request
    openssl ca -batch \
        -create_serial \
        -config ${CONFIG} \
        -days 3650 \
        -in ../${NAME_CSR} \
        -out ../${NAME_OUTPUT}

    popd
}

create_signed_certificate()
{
    local NAME=$1
    local CA_CONFIG=$2
    local CERT_CONFIG=$3

    local ECPARAM_FILE="ecdsaparam_${NAME}"
    local PRIVKEY="${NAME}privkey.pem"
    local PUBKEY="${NAME}pubkey.pem"
    local CSR="${NAME}req.pem"
    local SIGNED_CERT="${NAME}signed.pem"

    pushd $TMP_FOLDER

    # Create a Private key and a CSR
    openssl ecparam -name prime256v1 > ${ECPARAM_FILE}

    # Create a Certificate Signing Request
    openssl req -nodes -new \
        -newkey ec:${ECPARAM_FILE} \
        -config ${CERT_CONFIG} \
        -keyout ../${PRIVKEY} \
        -out ../${CSR}

    # Take a private key and generate a public key.
    openssl ec -in ../${PRIVKEY} -pubout -out ../${PUBKEY}

    popd

	# Sign the request
    sign_certificate ${CSR} ${SIGNED_CERT} ${CA_CONFIG}

    # Remove Certificate Signing Request
    rm ${CSR}
}


NAME="mainca"
generate_ca_identity ${NAME} ${CA_CONFIG}

# Participant 1
NAME="p1"
create_signed_certificate ${NAME} ${CA_CONFIG} ${APPLICATION_CONFIG}

# Participant 2
NAME="p2"
create_signed_certificate ${NAME} ${CA_CONFIG} ${APPLICATION_CONFIG}

# Remove tmp folder
rm -r $TMP_FOLDER
