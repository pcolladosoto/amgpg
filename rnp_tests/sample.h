#ifndef sample_h
#define sample_h

#include <stdio.h>
#include <string.h>
#include <rnp/rnp.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#define RNP_SUCCESS 0

#define PUBRING "keyrings/pubring.pgp"
#define SECRING "keyrings/secring.pgp"

#define DUMMY_KEY "sampleKey"

#define DUMMY_MSG "Hello there!"

typedef struct EncryptedMessage {
	uint8_t* enc_message;
	size_t enc_message_len;
	int result;
} encrypted_msg;

static bool example_pass_provider(rnp_ffi_t, void*, rnp_key_handle_t, const char*, char*, size_t);
static bool ffi_print_key(rnp_ffi_t, const char*, bool);
static bool ffi_export_key(rnp_ffi_t, const char*, bool);
int ffi_generate_keys(char const*, char const*);
int ffi_output_keys(char const*, char const*);

encrypted_msg ffi_encrypt(const char*, const char*, const char*);
#endif
