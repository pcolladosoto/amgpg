#include "sample.h"

int main(int argc, char** argv) {
	int res;

	if (argc != 1) {
		res = ffi_generate_keys(PUBRING, SECRING);
		if (res) {
			return res;
		}
	 	res = ffi_output_keys(PUBRING, SECRING);
		if (res) {
			return res;
    		}
	}

	encrypted_msg enc_msg = ffi_encrypt(DUMMY_MSG, PUBRING, DUMMY_KEY);
	fprintf(stdout, "%.*s", (int) enc_msg.enc_message_len, enc_msg.enc_message);

	// Time to free resources
	rnp_buffer_destroy(enc_msg.enc_message);

	return enc_msg.result;
}
