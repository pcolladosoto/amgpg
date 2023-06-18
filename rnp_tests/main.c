#include "rnp_tests.h"

msg_t read_file(const char* path) {
	msg_t message = {.msg = NULL, .len = 0, .ret = RNP_ERROR_GENERIC};
	int fd;

	if ((fd = open(path, O_RDONLY)) == -1)
		  return message;

	size_t fsize = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
	
	message.msg = (uint8_t*) malloc(fsize * sizeof(uint8_t));

	if (!message.msg)
		return message;

	message.len = fsize;
	message.ret = RNP_ERROR_GENERIC;

	if (read(fd, message.msg, fsize) == -1) {
		  free(message.msg);
		  return message;
	}

	close(fd);

	message.ret = RNP_SUCCESS;
	return message;
}

int main(int argc, char** argv) {
	int ret = -1;

	if (argc == 1) {
		fprintf(stderr, "usage: %s command [args]\n", argv[0]);
		return ret;
	}

	if (!strcmp(argv[1], "show")) {
		ret = amgpg_output_keys(PUBRING, SECRING);
	}
	else if (!strcmp(argv[1], "encrypt")) {
		if (argc != 3) {
			fprintf(stderr, "usage: %s %s path/to/file\n", argv[0], argv[1]);
			return ret;
		}

		msg_t dec_msg = read_file(argv[2]);
		if (dec_msg.ret != RNP_SUCCESS) {
			fprintf(stdout, "error reading back the file...\n");
			return ret;
		}

		fprintf(stderr, "%s\n", dec_msg.msg);

		msg_t enc_msg = amgpg_encrypt(dec_msg, PUBRING, SECRING, RECIPIENT);
		fprintf(stdout, "%.*s", (int) enc_msg.len, enc_msg.msg);
		ret = enc_msg.ret;
		rnp_buffer_destroy(enc_msg.msg);
		free(dec_msg.msg);
	}
	else if (!strcmp(argv[1], "decrypt")) {
		if (argc != 3) {
			fprintf(stderr, "usage: %s %s path/to/file\n", argv[0], argv[1]);
			return ret;
		}

		msg_t enc_msg = read_file(argv[2]);
		if (enc_msg.ret != RNP_SUCCESS) {
			fprintf(stdout, "error reading back the file...\n");
			return ret;
		}

		msg_t dec_msg = amgpg_decrypt(enc_msg, PUBRING, SECRING);
		fprintf(stdout, "%.*s", (int) dec_msg.len, dec_msg.msg);
		ret = dec_msg.ret;
		rnp_buffer_destroy(dec_msg.msg);
		free(enc_msg.msg);
	}
	else if (!strcmp(argv[1], "sign")) {
		if (argc != 3) {
			fprintf(stderr, "usage: %s %s path/to/file\n", argv[0], argv[1]);
			return ret;
		}

		msg_t enc_msg = read_file(argv[2]);
		if (enc_msg.ret != RNP_SUCCESS) {
			fprintf(stdout, "error reading back the file...\n");
			return ret;
		}

		msg_t sig_msg = amgpg_sign(enc_msg, PUBRING, SECRING, SENDER);
		fprintf(stdout, "%.*s", (int) sig_msg.len, sig_msg.msg);
		ret = sig_msg.ret;
		rnp_buffer_destroy(sig_msg.msg);
		free(enc_msg.msg);
	}
	else if (!strcmp(argv[1], "verify")) {
		if (argc != 3) {
			fprintf(stderr, "usage: %s %s path/to/file\n", argv[0], argv[1]);
			return ret;
		}

		msg_t sig_msg = read_file(argv[2]);
		if (sig_msg.ret != RNP_SUCCESS) {
			fprintf(stdout, "error reading back the file...\n");
			return ret;
		}

		msg_t ver_msg = amgpg_verify(sig_msg, PUBRING, SECRING);
		fprintf(stdout, "%.*s", (int) ver_msg.len, ver_msg.msg);
		ret = ver_msg.ret;
		rnp_buffer_destroy(ver_msg.msg);
		free(sig_msg.msg);
	}
	else {
		fprintf(stderr, "available commands: {show, encrypt, decrypt, sign, verify}\n");
	}

	return ret;
}
