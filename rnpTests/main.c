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

	res = ffi_encrypt(DUMMY_MSG, PUBRING, DUMMY_KEY);

	return res;
}
