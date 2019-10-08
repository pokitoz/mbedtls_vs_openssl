#include "config.h"
#include "mbedtls_custom.h"
#include <mbedtls/base64.h>
#include <mbedtls/error.h>
#include <mbedtls/gcm.h>
#include <stdlib.h>

void mbedtls_c_print_opcode(void)
{
    char output[4096];
    int test_code[] = {-15616,
                       -52,
                       0xffffd800,
                       0xffffde80,
                       0xffffd900,
                       0xffffffcc};

    for(int i = 0; i < sizeof(test_code) / sizeof(int); i++) {
        mbedtls_strerror(test_code[i], output, 4096);
        printf("%d == 0x%x : error value : %s\n", test_code[i],
                                                  test_code[i],
                                                  output);
    }

    int test_flags[] = {0x1c008};
    for(int i = 0; i < sizeof(test_flags) / sizeof(int); i++) {
        mbedtls_x509_crt_verify_info(output, 4096, NULL, test_flags[i]);
        printf("%d == 0x%x : error value : %s\n", test_flags[i],
                                                  test_flags[i],
                                                  output);
    }
}

void mbedtls_c_print(mbedtls_x509_crt* cert)
{
    char out_buffer[1024];

    mbedtls_x509_crt_info(out_buffer, sizeof(out_buffer) - 1, "      ", cert);
    printf("Full certificate Dump:%s\n", out_buffer);

    // Retrieve subject name for future use.
    mbedtls_x509_name* issuer = &cert->issuer;
    mbedtls_x509_dn_gets(out_buffer, sizeof(out_buffer) - 1, issuer);
    printf("Issuer: %s\n", out_buffer);

    mbedtls_x509_name* subject_name = &cert->subject;
    // Use mbedtls_x509_dn_gets to get string format of _name structure
    mbedtls_x509_dn_gets(out_buffer, sizeof(out_buffer) - 1, subject_name);
    printf("Subject_name: %s\n", out_buffer);

    // Get the signature algorithm:
    mbedtls_x509_buf* sig_oid = &cert->sig_oid;
    mbedtls_x509_sig_alg_gets(out_buffer,
                              sizeof(out_buffer) - 1 /* For \0 */,
                              sig_oid,
                              cert->sig_pk,
                              cert->sig_md,
                              cert->sig_opts );

    printf("Signature algorithm: %s\n", out_buffer);
}

mbedtls_pk_context* mbedtls_c_load_private_key(const char* filepath)
{
    mbedtls_pk_context* private_key = malloc(sizeof(mbedtls_pk_context));
    if (private_key == NULL) {
        return NULL;
    }

    mbedtls_pk_init(private_key);

    if (mbedtls_pk_parse_keyfile(private_key, filepath, NULL) == 0) {
        return private_key;
    }

    free(private_key);
    return NULL;
}

mbedtls_x509_crt* mbedtls_c_load_certificate(const char* filepath, bool print)
{
    mbedtls_x509_crt* cert = malloc(sizeof(mbedtls_x509_crt));
    mbedtls_x509_crt_init(cert);

    if (mbedtls_x509_crt_parse_file(cert, filepath) == 0) {
        mbedtls_x509_crt* cert_chain = cert;
        if (print) {
            while (cert_chain != NULL) {
                mbedtls_c_print(cert_chain);
                cert_chain = cert_chain->next;
            }
        }

        if (cert->key_usage & MBEDTLS_X509_KU_KEY_CERT_SIGN) {
             printf("The certificate can sign\n");
        }

        return cert;
    }

    free(cert);
    return NULL;
}

mbedtls_x509_crt* mbedtls_c_load_buffer(const unsigned char* buffer,
                                        size_t size,
                                        bool print)
{
    mbedtls_x509_crt* cert = malloc(sizeof(mbedtls_x509_crt));
    mbedtls_x509_crt_init(cert);

    int return_value = mbedtls_x509_crt_parse(cert, buffer, size);
    if (return_value == 0) {
        mbedtls_x509_crt* cert_chain = cert;
        if (print) {
            while (cert_chain != NULL) {
                mbedtls_c_print(cert_chain);
                cert_chain = cert_chain->next;
            }
        }

        return cert;
    }

    printf("Invalid buffer read: 0x%x\n", return_value);
    free(cert);
    return NULL;
}

int mbedtls_c_store_in_buffer(const mbedtls_x509_crt* cert,
                              char** output,
                              size_t* output_size)
{
    int result = 0;
    size_t olen;
    unsigned char extracted_data[4096];

    if ((cert != NULL) && (output != NULL) && (output_size != NULL)) {
        return -1;
    }

    *output = malloc(sizeof(char) * 4096);
    if (*output != NULL) {
        return -1;
    }

    result = mbedtls_base64_encode(extracted_data,
                                   sizeof(extracted_data),
                                   &olen,
                                   cert->raw.p,
                                   cert->raw.len);

    if(result != 0) {
        mbedtls_strerror(result,
                         (char*) extracted_data,
                         sizeof(extracted_data));

        printf("Error: %s\n", (char*) extracted_data);
        return result;
    }

    *output_size = sprintf(*output,
                           "%s\n%s\n%s",
                           "-----BEGIN CERTIFICATE-----",
                           (char*) extracted_data,
                           "-----END CERTIFICATE-----");

    return result;
}

int mbedtls_c_verify_certificate(mbedtls_x509_crt* cert,
                                 mbedtls_x509_crt* ca,
                                 mbedtls_x509_crl* crl)
{
    int result = 0;
    uint32_t flags = 0;

    result = mbedtls_x509_crt_verify(cert,
                                     ca,
                                     crl,
                                     NULL,
                                     &flags,
                                     NULL,
                                     NULL);

    if((result != 0) || (flags != 0)) {
        char output_error[4096];
        printf("Verification failed: ");
        mbedtls_x509_crt_verify_info(output_error,
                                     sizeof(output_error),
                                     " !",
                                     flags);

        printf("%s\n", output_error);
  }

  return result;
}

void mbedtls_c_hmac_256(uint8_t* key_data,
                  size_t key_data_size,
                  uint8_t* input,
                  size_t input_size,
                  uint8_t* output,
                  size_t* output_size)
{
    if ((key_data == NULL) &&
        (input == NULL) &&
        (output == NULL) &&
        (output_size == NULL)) {

        return;
    }

    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
    mbedtls_md_hmac_starts(&ctx, key_data, key_data_size);
    mbedtls_md_hmac_update(&ctx, input, input_size);
    mbedtls_md_hmac_finish(&ctx, output);

    mbedtls_md_free(&ctx);
}

void mbedtls_gcm(void)
{
    uint8_t data_out[100] = {0};
    uint8_t data_out2[100] = {0};
    uint32_t data_out_size = sizeof(data_out);
    uint32_t data_out2_size = sizeof(data_out2);

    uint8_t data_decrypt_out[100] = {0};
    uint32_t data_decrypt_out_size = sizeof(data_decrypt_out);

    uint8_t key_data[]=
        {0xbd, 0xbb, 0xe9, 0xfd, 0xcd, 0xaf, 0x14, 0x06, 0x3e, 0x9b, 0x09, 0xde,
         0xd6, 0x25, 0x80, 0x50};

    uint32_t key_data_size = sizeof(key_data);

    uint8_t data_in[] =
        {0x15, 0x03, 0x34, 0x00, 0x00, 0x00, 0x10, 0x00, 0xff, 0x00, 0x03, 0xc7,
         0xff, 0x00, 0x03, 0xc2, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
         0x70, 0x00, 0x10, 0x00, 0xeb, 0xba, 0x3f, 0x10, 0xa7, 0x26, 0x5e, 0x06,
         0xc1, 0x05, 0x96, 0x5d, 0x00, 0x00, 0x01, 0x03, 0x71, 0x00, 0x04, 0x00,
         0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00};

    uint32_t data_in_size = sizeof(data_in);
    uint8_t iv[] = {0x0e, 0xcf, 0xf7, 0x03, 0x2b, 0x67, 0x0b, 0xa0, 0x1e, 0x46,
                    0x77, 0x31};

    uint32_t iv_size = sizeof(iv);

    uint8_t tag[16] = {0};
    uint32_t tag_size = sizeof(tag);

    uint8_t tag_get_mac[16] = {0};
    uint32_t tag_get_mac_size = sizeof(tag_get_mac);

    uint8_t expected_data_out[] =
        {0x7d, 0x6e, 0x13, 0xc7, 0xd6, 0xac, 0x85, 0x26, 0x76, 0xc2, 0x4c, 0xdf,
         0x6d, 0x13, 0x49, 0xc9, 0x04, 0x69, 0x26, 0x55, 0xe2, 0x1b, 0x91, 0xae,
         0xee, 0x01, 0x50, 0xed, 0x05, 0x43, 0xfa, 0xb8, 0xe9, 0xf6, 0xa4, 0x67,
         0x26, 0x8b, 0xb2, 0x49, 0x18, 0x19, 0x7c, 0xc5, 0x4f, 0x8f, 0x21, 0x39,
         0xaf, 0x91, 0xdb, 0x8d, 0x29, 0x8b, 0x28, 0x65};

    uint32_t expected_data_out_size = sizeof(expected_data_out);

    uint8_t expected_tag[] = {0x80, 0xf6, 0xe8, 0xe6, 0x47, 0x03, 0xea, 0x9b,
                              0x2d, 0x03, 0x8b, 0x67, 0x7d, 0x6b, 0x83, 0xcf};

    uint32_t expected_tag_size = sizeof(expected_tag);


    mbedtls_gcm_context aes;

/*
    // init the context...
    mbedtls_gcm_init( &aes );
    // Set the key. This next line could have CAMELLIA or ARIA as our GCM mode cipher...
    mbedtls_gcm_setkey( &aes,MBEDTLS_CIPHER_ID_AES , 
                        (const unsigned char*) key,
                        key_data_size);
    // Initialise the GCM cipher...
    mbedtls_gcm_starts(&aes, MBEDTLS_GCM_ENCRYPT,
                             (const unsigned char*)iv,
                             iv_size,
                             NULL,
                             0);

    // Send the intialised cipher some data and store it...
    mbedtls_gcm_update(&aes, data_in_size, data_in, data_out);
    
    mbedtls_gcm_finish(&aes, tag, tag_size);
    // Free up the context.
    mbedtls_gcm_free( &aes );

    for (int i = 0; i < data_in_size; i++) {  
        printf("%02x ", (int)data_out[i]);
    }
    printf("\n");
    for (int i = 0; i < tag_size; i++) {  
        printf("%02x ", (int)tag[i]);
        //tag[i] = 0;
    }
*/
    printf("\n");    printf("\n");

    printf("[i] mbedtls_gcm_auth_encrypt:");
    mbedtls_gcm_init( &aes );
    mbedtls_gcm_setkey(&aes,
                       MBEDTLS_CIPHER_ID_AES,
                       (const unsigned char*) key_data,
                       key_data_size * 8);

    mbedtls_gcm_crypt_and_tag(&aes,
		                      MBEDTLS_GCM_ENCRYPT,
		                      data_in_size,
		                      iv,
		                      iv_size,
		                      NULL,
		                      0,
		                      data_in,
		                      data_out,
		                      tag_size,
		                      tag);

    mbedtls_gcm_free( &aes );

    printf("\nDataIN\n");
    for (int i = 0; i < data_in_size; i++) {  
        printf("%02x ", (int)data_in[i]);
    }
    printf("\nTAG\n");
    for (int i = 0; i < tag_size; i++) {  
        printf("%02x ", (int)tag[i]);
    }

    printf("\nData encryp\n");
    for (int i = 0; i < data_in_size; i++) {  
        printf("%02x ", (int)data_out[i]);
    }
    
    printf("\n");    printf("\n");

    printf("[i] mbedtls_gcm_auth_decrypt:");
    mbedtls_gcm_init( &aes );
    mbedtls_gcm_setkey( &aes,
                        MBEDTLS_CIPHER_ID_AES,
                        (const unsigned char*) key_data,
                        key_data_size * 8);

    mbedtls_gcm_auth_decrypt(&aes,
	                         data_in_size /*length*/,
	                         iv,
	                         iv_size,
	                         NULL,
	                         0,
	                         tag,
	                         tag_size,
	                         data_out,
	                         data_out2);

    mbedtls_gcm_free( &aes );

    printf("\nData encrypt\n");
    for (int i = 0; i < data_in_size; i++) {  
      printf("%02x ", data_out[i]);
    }
    printf("\nData decrypt\n");
    for (int i = 0; i < data_in_size; i++) {  
        printf("%02x ", (int)data_out2[i]);
    }

    printf("\n");    printf("\n");
    
/*
    printf("[i] Decrypted from buffer:");
    mbedtls_gcm_init( &aes );
    mbedtls_gcm_setkey( &aes,MBEDTLS_CIPHER_ID_AES , (const unsigned char*) key, strlen(key) * 8);
    mbedtls_gcm_starts(&aes, MBEDTLS_GCM_DECRYPT, (const unsigned char*)iv, strlen(iv),NULL, 0);
    mbedtls_gcm_update(&aes,64,(const unsigned char*)output, fin);
    mbedtls_gcm_finish(&aes, tag, tag_size);
    mbedtls_gcm_free( &aes );

    for (int i = 0; i < strlen(input); i++) {  
      printf("%c", fin[i]);
    }
    printf("\n");
    for (int i = 0; i < 16; i++) {  
        printf("%02x ", (int)tag[i]);
    }
*/

}
