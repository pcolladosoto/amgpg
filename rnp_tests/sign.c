#include "rnp_tests.h"

msg_t amgpg_sign(msg_t message, const char* pubring, const char* secring, const char* sender) {
	rnp_ffi_t        ffi = NULL;
	rnp_input_t      keyfile = NULL;
	rnp_input_t      input = NULL;
	rnp_output_t     output = NULL;
	rnp_op_sign_t    sign = NULL;
	rnp_key_handle_t key = NULL;
	uint8_t *        buf = NULL;
	size_t           buf_len = 0;
	rnp_result_t     ret = RNP_ERROR_GENERIC;

	if ((ret = rnp_ffi_create(&ffi, PUBTYPE, SECTYPE)) != RNP_SUCCESS)
		return (msg_t) {buf, buf_len, ret};

	if ((ret = load_keys(ffi, pubring, secring)) != RNP_SUCCESS)
		goto finish;

	/* set the password provider - we'll need password to unlock secret keys */
	// rnp_ffi_set_pass_provider(ffi, example_pass_provider, NULL);

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

	/* initialize and configure sign operation, use
	 * rnp_op_sign_create_cleartext/rnp_op_sign_create_detached for cleartext or detached
	 * signature. */
	if ((ret = rnp_op_sign_cleartext_create(&sign, ffi, input, output)) != RNP_SUCCESS) {
		fprintf(stdout, "failed to create sign operation\n");
		goto finish;
	}

	/* armor, file name, compression */
	rnp_op_sign_set_armor(sign, true);
	rnp_op_sign_set_file_name(sign, "message.sig");
	rnp_op_sign_set_file_mtime(sign, (uint32_t) time(NULL));
	rnp_op_sign_set_compression(sign, "ZIP", 6);
	/* signatures creation time - by default will be set to the current time as well */
	rnp_op_sign_set_creation_time(sign, (uint32_t) time(NULL));
	/* signatures expiration time - by default will be 0, i.e. never expire */
	// rnp_op_sign_set_expiration_time(sign, 365 * 24 * 60 * 60);
	/* set hash algorithm - should be compatible for all signatures */
	rnp_op_sign_set_hash(sign, RNP_ALGNAME_SHA256);

	// Time to get the key!
	if ((ret = amgpg_load_key_by_email(ffi, sender, &key)) != RNP_SUCCESS) {
		fprintf(stdout, "failed to locate recipient key with email %s.\n", sender);
		goto finish;
	}

	/* we do not need pointer to the signature so passing NULL as the last parameter */
	if ((ret = rnp_op_sign_add_signature(sign, key, NULL)) != RNP_SUCCESS) {
		fprintf(stdout, "failed to add signature for key rsa@key.\n");
		goto finish;
	}

	/* do not forget to destroy key handle */
	rnp_key_handle_destroy(key);
	key = NULL;

	/* finally do signing */
	if ((ret = rnp_op_sign_execute(sign)) != RNP_SUCCESS) {
		fprintf(stdout, "failed to sign\n");
		goto finish;
	}

	// Retrieve memory buffer
	if ((ret = rnp_output_memory_get_buf(output, &buf, &buf_len, true)) != RNP_SUCCESS) {
		fprintf(stderr, "error retrieving the output buffer...\n");
		goto finish;
	}

finish:
	rnp_input_destroy(keyfile);
	rnp_key_handle_destroy(key);
	rnp_op_sign_destroy(sign);
	rnp_input_destroy(input);
	rnp_output_destroy(output);
	rnp_ffi_destroy(ffi);
	return (msg_t) {buf, buf_len, ret};
}
