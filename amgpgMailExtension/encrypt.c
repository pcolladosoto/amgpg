#include "amgpg_rnp.h"

msg_t amgpg_encrypt(msg_t dec_message, const char* pubring, const char* secring, const char* recipient) {
    rnp_ffi_t        ffi = NULL;
    rnp_op_encrypt_t encrypt = NULL;
    rnp_key_handle_t key = NULL;
    rnp_input_t      input = NULL;
    rnp_output_t     output = NULL;
    uint8_t *        buf = NULL;
    size_t           buf_len = 0;
    rnp_result_t     ret = RNP_ERROR_GENERIC;

    // Initialize FFI object.
    if ((ret = rnp_ffi_create(&ffi, PUBTYPE, SECTYPE)) != RNP_SUCCESS) {
        return (msg_t) {buf, buf_len, ret};
    }

    if ((ret = load_keys(ffi, pubring, secring)) != RNP_SUCCESS)
        goto finish;

    // Create memory input and file output objects for the message and encrypted message.
    if ((ret = rnp_input_from_memory(&input, dec_message.msg, dec_message.len, false)) != RNP_SUCCESS) {
        fprintf(stdout, "failed to create input object\n");
        goto finish;
    }

    if ((ret = rnp_output_to_memory(&output, 0)) != RNP_SUCCESS) {
        fprintf(stdout, "failed to create output object\n");
        goto finish;
    }

    // Create encryption operation.
    if ((ret = rnp_op_encrypt_create(&encrypt, ffi, input, output)) != RNP_SUCCESS) {
        fprintf(stdout, "failed to create encrypt operation\n");
        goto finish;
    }

    // Setup encryption parameters.
    rnp_op_encrypt_set_armor(encrypt, true);
    rnp_op_encrypt_set_file_name(encrypt, "message.enc");
    rnp_op_encrypt_set_file_mtime(encrypt, (uint32_t) time(NULL));
    rnp_op_encrypt_set_compression(encrypt, "ZIP", 6);
    rnp_op_encrypt_set_cipher(encrypt, RNP_ALGNAME_AES_256);
    rnp_op_encrypt_set_aead(encrypt, "None");

    // Time to get the key!
    if ((ret = amgpg_load_key_by_email(ffi, recipient, &key)) != RNP_SUCCESS) {
        fprintf(stdout, "failed to locate recipient key with email %s.\n", recipient);
        goto finish;
    }

    if ((ret = rnp_op_encrypt_add_recipient(encrypt, key)) != RNP_SUCCESS) {
        fprintf(stdout, "failed to add recipient\n");
        goto finish;
    }

    rnp_key_handle_destroy(key);
    key = NULL;

    // We could add an encryption password as well...
    /*
        if (rnp_op_encrypt_add_password(
            encrypt, "encpassword", RNP_ALGNAME_SHA256, 0, RNP_ALGNAME_AES_256) != RNP_SUCCESS) {
            fprintf(stdout, "failed to add encryption password\n");
            goto finish;
        }
    */

    // Execute encryption operation.
    if ((ret = rnp_op_encrypt_execute(encrypt)) != RNP_SUCCESS) {
        fprintf(stdout, "encryption failed\n");
        goto finish;
    }

    // fprintf(stdout, "Encryption succeeded. Encrypted message written to memory buffer.\n");

    // Retrieve memory buffer
    if ((ret = rnp_output_memory_get_buf(output, &buf, &buf_len, true)) != RNP_SUCCESS) {
        fprintf(stderr, "error retrieving the output buffer...\n");
        goto finish;
    }

finish:
    rnp_op_encrypt_destroy(encrypt);
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    rnp_key_handle_destroy(key);
    rnp_ffi_destroy(ffi);

    return (msg_t) {buf, buf_len, ret};
}
