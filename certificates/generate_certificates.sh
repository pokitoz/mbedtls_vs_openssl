#!/bin/bash

set -e

TMP_FOLDER=./tmp

generate_ca_identity()
{
    NAME_CA=$1

    CONFIG_FOLDER=./cnf_files
    rm -rf $TMP_FOLDER

    mkdir -p $TMP_FOLDER
    cp $CONFIG_FOLDER/appconf.cnf $TMP_FOLDER
    cp $CONFIG_FOLDER/maincaconf.cnf $TMP_FOLDER

    pushd $TMP_FOLDER

    openssl ecparam -name prime256v1 > ecdsaparam_${NAME_CA}

    openssl req -nodes \
        -x509 \
        -days 3650 \
        -newkey ec:ecdsaparam_${NAME_CA} \
        -keyout ${NAME_CA}key.pem \
        -out ${NAME_CA}cert.pem \
        -config ${NAME_CA}conf.cnf

    touch index.txt
    
    popd

}

sign_certificate()
{
    NAME_CSR=$1
    NAME_CA=$2
	NAME_OUTPUT=$3

    pushd $TMP_FOLDER

    # Ask CA to sign Certificate Request
    openssl ca -batch \
        -create_serial \
        -config ${NAME_CA}conf.cnf \
        -days 3650 \
        -in ../${NAME_CSR} \
        -out ../${NAME_OUTPUT}

    popd
}

create_signed_certificate()
{
    NAME=$1
    NAME_CA=$2

    pushd $TMP_FOLDER

    # Create a Private key and a CSR
    openssl ecparam -name prime256v1 > ecdsaparam_${NAME}

    # Create a Certificate Signing Request
    openssl req -nodes -new \
        -newkey ec:ecdsaparam_${NAME} \
        -config appconf.cnf \
        -keyout ../${NAME}privkey.pem \
        -out ../${NAME}req.pem

    # Take a private key and generate a public key.
    openssl ec -in ../${NAME}privkey.pem \
               -pubout \
               -out ../${NAME}pubkey.pem

    popd

	# Sign the request
    sign_certificate ${NAME}req.pem $NAME_CA ${NAME}signed.pem

    # Remove Certificate Signing Request
    rm ./${NAME}req.pem
}


NAME_CA="mainca"
generate_ca_identity $NAME_CA

# Participant 1
NAME=p1
create_signed_certificate $NAME $NAME_CA

# Participant 2
NAME=p2
create_signed_certificate $NAME $NAME_CA

# Copy the CA certificate
cp $TMP_FOLDER/${NAME_CA}cert.pem ./
# Remove tmp folder
rm -r $TMP_FOLDER
