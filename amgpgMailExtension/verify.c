#include "amgpg_rnp.h"

msg_t amgpg_verify(msg_t message, const char* pubring, const char* secring) {
    rnp_ffi_t       ffi = NULL;
    rnp_op_verify_t verify = NULL;
    rnp_input_t     input = NULL;
    rnp_output_t    output = NULL;
    uint8_t *       buf = NULL;
    size_t          buf_len = 0;
    size_t          sigcount = 0;
    rnp_result_t    ret = 1;

    /* initialize FFI object */
    if ((ret = rnp_ffi_create(&ffi, PUBTYPE, SECTYPE)) != RNP_SUCCESS) {
        return (msg_t) {buf, buf_len, ret};
    }

    if ((ret = load_keys(ffi, pubring, secring)) != RNP_SUCCESS)
        goto finish;

    /* create file input and memory output objects for the encrypted message and decrypted
     * message */
    if ((ret = rnp_input_from_memory(&input, message.msg, message.len, false)) != RNP_SUCCESS) {
        fprintf(stdout, "failed to create input object\n");
        goto finish;
    }

    if ((ret = rnp_output_to_memory(&output, 0)) != RNP_SUCCESS) {
        fprintf(stdout, "failed to create output object\n");
        goto finish;
    }

    if ((ret = rnp_op_verify_create(&verify, ffi, input, output)) != RNP_SUCCESS) {
        fprintf(stdout, "failed to create verification context\n");
        goto finish;
    }

    if ((ret = rnp_op_verify_execute(verify)) != RNP_SUCCESS) {
        fprintf(stdout, "failed to execute verification operation\n");
        goto finish;
    }

    /* now check signatures and get some info about them */
    if ((ret = rnp_op_verify_get_signature_count(verify, &sigcount)) != RNP_SUCCESS) {
        fprintf(stdout, "failed to get signature count\n");
        goto finish;
    }

    for (size_t i = 0; i < sigcount; i++) {
        rnp_op_verify_signature_t sig = NULL;
        rnp_key_handle_t          key = NULL;
        char *                    keyid = NULL;

        if ((ret = rnp_op_verify_get_signature_at(verify, i, &sig)) != RNP_SUCCESS) {
            fprintf(stdout, "failed to get signature %d\n", (int) i);
            goto finish;
        }

        if ((ret = rnp_op_verify_signature_get_key(sig, &key)) != RNP_SUCCESS) {
            fprintf(stdout, "failed to get signature's %d key\n", (int) i);
            goto finish;
        }

        if ((ret = rnp_key_get_keyid(key, &keyid)) != RNP_SUCCESS) {
            fprintf(stdout, "failed to get key id %d\n", (int) i);
            rnp_key_handle_destroy(key);
            goto finish;
        }

        if ((ret = rnp_op_verify_signature_get_status(sig)) != RNP_SUCCESS) {
            rnp_buffer_destroy(keyid);
            rnp_key_handle_destroy(key);
            goto finish;
        }

        fprintf(stdout, "Status for signature from key %s : %d\n", keyid, (int) ret);
        rnp_buffer_destroy(keyid);
        rnp_key_handle_destroy(key);
    }

    /* get the verified message from the output structure */
    if ((ret = rnp_output_memory_get_buf(output, &buf, &buf_len, true)) != RNP_SUCCESS) {
        goto finish;
    }

finish:
    rnp_op_verify_destroy(verify);
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    rnp_ffi_destroy(ffi);
    return (msg_t) {buf, buf_len, ret};
}
