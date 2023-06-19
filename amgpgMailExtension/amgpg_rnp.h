#ifndef AMGPG_RNP
#define AMGPG_RNP

#include <stdio.h>
#include <string.h>
#include <rnp/rnp.h>
#include <rnp/rnp_err.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#define PUBRING "keyrings/pubring.kbx"
#define SECRING "keyrings/secring"

#define PUBTYPE RNP_KEYSTORE_KBX
#define SECTYPE RNP_KEYSTORE_G10

typedef struct message {
    uint8_t* msg;
    size_t len;
    rnp_result_t ret;
} msg_t;

// Key management
void         amgpg_print_n_keys(rnp_ffi_t);
rnp_result_t amgpg_print_key(rnp_ffi_t, const char*, const char*, bool);
rnp_result_t amgpg_print_keys(rnp_ffi_t ffi, const char* id_type, bool secret);
rnp_result_t amgpg_load_key_by_email(rnp_ffi_t, const char*, rnp_key_handle_t*);
rnp_result_t load_keys(rnp_ffi_t, const char*, const char*);
rnp_result_t amgpg_output_keys(char const*, char const*);
rnp_result_t amgpg_key_is(const char*, const char*, const char*, bool);

// Security ops
msg_t amgpg_encrypt(msg_t, const char*, const char*, const char*);
msg_t amgpg_decrypt(msg_t, const char*, const char*);
msg_t amgpg_sign(msg_t, const char*, const char*, const char*);
msg_t amgpg_verify(msg_t, const char*, const char*);
#endif
