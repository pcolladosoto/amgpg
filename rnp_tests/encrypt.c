#include "sample.h"

encrypted_msg ffi_encrypt(const char* message, const char* pubring, const char* userid) {
    rnp_ffi_t        ffi = NULL;
    rnp_op_encrypt_t encrypt = NULL;
    rnp_key_handle_t key = NULL;
    rnp_input_t      keyfile = NULL;
    rnp_input_t      input = NULL;
    rnp_output_t     output = NULL;
    uint8_t *        buf = NULL;
    size_t           buf_len = 0;
    int              result = 1;

    // Initialize FFI object.
    if (rnp_ffi_create(&ffi, "GPG", "GPG") != RNP_SUCCESS) {
        return (encrypted_msg) {buf, buf_len, result};
    }

    // Load public keyring - we do not need secret for encryption.
    if (rnp_input_from_path(&keyfile, pubring) != RNP_SUCCESS) {
        fprintf(stdout, "failed to open %s. Did you run ./generate sample?\n", pubring);
        goto finish;
    }

    // We may use RNP_LOAD_SAVE_SECRET_KEYS | RNP_LOAD_SAVE_PUBLIC_KEYS as well.
    if (rnp_load_keys(ffi, "GPG", keyfile, RNP_LOAD_SAVE_PUBLIC_KEYS) != RNP_SUCCESS) {
        fprintf(stdout, "failed to read pubring.pgp\n");
        goto finish;
    }
    rnp_input_destroy(keyfile);
    keyfile = NULL;

    // Create memory input and file output objects for the message and encrypted message.
    if (rnp_input_from_memory(&input, (uint8_t *) message, strlen(message), false) !=
        RNP_SUCCESS) {
        fprintf(stdout, "failed to create input object\n");
        goto finish;
    }

    if (rnp_output_to_memory(&output, 0) != RNP_SUCCESS) {
        fprintf(stdout, "failed to create output object\n");
        goto finish;
    }

    // Create encryption operation.
    if (rnp_op_encrypt_create(&encrypt, ffi, input, output) != RNP_SUCCESS) {
        fprintf(stdout, "failed to create encrypt operation\n");
        goto finish;
    }

    // Setup encryption parameters.
    rnp_op_encrypt_set_armor(encrypt, true);
    rnp_op_encrypt_set_file_name(encrypt, "encMessage.txt");
    rnp_op_encrypt_set_file_mtime(encrypt, time(NULL));
    rnp_op_encrypt_set_compression(encrypt, "ZIP", 6);
    rnp_op_encrypt_set_cipher(encrypt, RNP_ALGNAME_AES_256);
    rnp_op_encrypt_set_aead(encrypt, "None");

    // Locate recipient's key and add it to the operation context. While we search by userid
        // (which is easier), you can search by keyid, fingerprint or grip.
    if (rnp_locate_key(ffi, "userid", userid, &key) != RNP_SUCCESS) {
        fprintf(stdout, "failed to locate recipient key with userid %s.\n", userid);
        goto finish;
    }

    if (rnp_op_encrypt_add_recipient(encrypt, key) != RNP_SUCCESS) {
        fprintf(stdout, "failed to add recipient\n");
        goto finish;
    }
    rnp_key_handle_destroy(key);
    key = NULL;

    // Add encryption password as well.
    // if (rnp_op_encrypt_add_password(
    //      encrypt, "encpassword", RNP_ALGNAME_SHA256, 0, RNP_ALGNAME_AES_256) != RNP_SUCCESS) {
    //    fprintf(stdout, "failed to add encryption password\n");
    //    goto finish;
    // }

    // Execute encryption operation.
    if (rnp_op_encrypt_execute(encrypt) != RNP_SUCCESS) {
        fprintf(stdout, "encryption failed\n");
        goto finish;
    }

    fprintf(stdout, "Encryption succeeded. Encrypted message written to memory buffer.\n");

    // Retrieve memeory buffer
    if (rnp_output_memory_get_buf(output, &buf, &buf_len, true) != RNP_SUCCESS) {
	    fprintf(stderr, "error retrieving the output buffer...\n");
	    goto finish;
    }

    // fprintf(stdout, "%.*s", (int) buf_len, buf);

    result = 0;
finish:
    rnp_op_encrypt_destroy(encrypt);
    rnp_input_destroy(keyfile);
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    rnp_key_handle_destroy(key);
    rnp_ffi_destroy(ffi);

    return (encrypted_msg) {buf, buf_len, result};
}
