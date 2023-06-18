#include "rnp_tests.h"

msg_t amgpg_decrypt(msg_t enc_msg, const char* pubring, const char* secring) {
	rnp_ffi_t    ffi = NULL;
	rnp_input_t  input = NULL;
	rnp_output_t output = NULL;
	uint8_t *    buf = NULL;
	size_t       buf_len = 0;
	rnp_result_t ret = 1;

	/* initialize FFI object */
	if ((ret = rnp_ffi_create(&ffi, PUBTYPE, SECTYPE)) != RNP_SUCCESS)
		return (msg_t) {buf, buf_len, ret};

	if ((ret = load_keys(ffi, pubring, secring)) != RNP_SUCCESS)
		goto finish;

	if ((ret = rnp_input_from_memory(&input, enc_msg.msg, enc_msg.len, true)) != RNP_SUCCESS) {
		fprintf(stdout, "failed to create input object\n");
		goto finish;
	}

	if ((ret = rnp_output_to_memory(&output, 0)) != RNP_SUCCESS) {
		fprintf(stdout, "failed to create output object\n");
		goto finish;
	}

	if ((ret = rnp_decrypt(ffi, input, output)) != RNP_SUCCESS) {
		fprintf(stdout, "public-key decryption failed\n");
		goto finish;
	}

	/* get the decrypted message from the output structure */
	if ((ret = rnp_output_memory_get_buf(output, &buf, &buf_len, true)) != RNP_SUCCESS) {
		goto finish;
	}

finish:
	rnp_input_destroy(input);
	rnp_output_destroy(output);
	rnp_ffi_destroy(ffi);

	return (msg_t) {buf, buf_len, ret};
}
