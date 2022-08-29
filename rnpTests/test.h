#ifndef test_h
#define test_h

#include <stdio.h>
#include <string.h>
#include <rnp/rnp.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define RNP_SUCCESS 0

static bool example_pass_provider(rnp_ffi_t, void*, rnp_key_handle_t, const char*, char*, size_t);
static bool ffi_print_key(rnp_ffi_t, const char*, bool);
static bool ffi_export_key(rnp_ffi_t, const char*, bool);
static int ffi_generate_keys(void);
static int ffi_output_keys(void);
#endif
