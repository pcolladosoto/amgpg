#include "sample.h"

/* RSA key JSON description. 31536000 = 1 year expiration, 15768000 = half year */
const char *RSA_KEY_DESC = "{\
    'primary': {\
        'type': 'RSA',\
        'length': 2048,\
        'userid': 'sampleKey',\
        'expiration': 31536000,\
        'usage': ['sign'],\
        'protection': {\
            'cipher': 'AES256',\
            'hash': 'SHA256'\
        }\
    },\
    'sub': {\
        'type': 'RSA',\
        'length': 2048,\
        'expiration': 15768000,\
        'usage': ['encrypt'],\
        'protection': {\
            'cipher': 'AES256',\
            'hash': 'SHA256'\
        }\
    }\
}";

// We'll just pass a mock password whenever we are prompted for one.
	// We'll likely read it from stdin after stuff looks better!
static bool example_pass_provider(rnp_ffi_t ffi, void* app_ctx, rnp_key_handle_t key, const char* pgp_context,
	char buf[], size_t buf_len) {
    if (strcmp(pgp_context, "protect")) {
        return false;
    }

    strncpy(buf, "password", buf_len);
    return true;
}

// This simple helper function just prints armored key, searched by userid, to stderr.
static bool ffi_print_key(rnp_ffi_t ffi, const char *uid, bool secret) {
    rnp_output_t     keydata = NULL;
    rnp_key_handle_t key = NULL;
    uint32_t         flags = RNP_KEY_EXPORT_ARMORED | RNP_KEY_EXPORT_SUBKEYS;
    uint8_t *        buf = NULL;
    size_t           buf_len = 0;
    bool             result = false;

    // You may search for the key via userid, keyid, fingerprint, grip.
    if (rnp_locate_key(ffi, "userid", uid, &key) != RNP_SUCCESS) {
        return false;
    }

    if (!key) {
        return false;
    }

    // Create in-memory output structure to later use buffer.
    if (rnp_output_to_memory(&keydata, 0) != RNP_SUCCESS) {
        goto finish;
    }

    flags = flags | (secret ? RNP_KEY_EXPORT_SECRET : RNP_KEY_EXPORT_PUBLIC);
    if (rnp_key_export(key, keydata, flags) != RNP_SUCCESS) {
        goto finish;
    }

    // Get key's contents from the output structure.
    if (rnp_output_memory_get_buf(keydata, &buf, &buf_len, false) != RNP_SUCCESS) {
        goto finish;
    }
    fprintf(stderr, "%.*s", (int) buf_len, buf);

    result = true;
finish:
    rnp_key_handle_destroy(key);
    rnp_output_destroy(keydata);
    return result;
}

static bool ffi_export_key(rnp_ffi_t ffi, const char *uid, bool secret) {
    rnp_output_t     keyfile = NULL;
    rnp_key_handle_t key = NULL;
    uint32_t         flags = RNP_KEY_EXPORT_ARMORED | RNP_KEY_EXPORT_SUBKEYS;
    char             filename[32] = {0};
    char *           keyid = NULL;
    bool             result = false;

    /* you may search for the key via userid, keyid, fingerprint, grip */
    if (rnp_locate_key(ffi, "userid", uid, &key) != RNP_SUCCESS) {
        return false;
    }

    if (!key) {
        return false;
    }

    /* get key's id and build filename */
    if (rnp_key_get_keyid(key, &keyid) != RNP_SUCCESS) {
        goto finish;
    }
    snprintf(filename, sizeof(filename), "key-%s-%s.asc", keyid, secret ? "sec" : "pub");
    rnp_buffer_destroy(keyid);

    /* create file output structure */
    if (rnp_output_to_path(&keyfile, filename) != RNP_SUCCESS) {
        goto finish;
    }

    flags = flags | (secret ? RNP_KEY_EXPORT_SECRET : RNP_KEY_EXPORT_PUBLIC);
    if (rnp_key_export(key, keyfile, flags) != RNP_SUCCESS) {
        goto finish;
    }

    result = true;
finish:
    rnp_key_handle_destroy(key);
    rnp_output_destroy(keyfile);
    return result;
}

// This example generates a single RSA key
int ffi_generate_keys(char const* pubring, char const* secring) {
    rnp_ffi_t    ffi = NULL;
    rnp_output_t keyfile = NULL;
    char *       key_grips = NULL;
    int          result = 1;

    // Initialize FFI object
    if (rnp_ffi_create(&ffi, "GPG", "GPG") != RNP_SUCCESS) {
        return result;
    }

    // Set password provider
    if (rnp_ffi_set_pass_provider(ffi, example_pass_provider, NULL)) {
        goto finish;
    }

    // Generate RSA keypair
    if (rnp_generate_key_json(ffi, RSA_KEY_DESC, &key_grips) != RNP_SUCCESS) {
        fprintf(stderr, "failed to generate rsa key\n");
        goto finish;
    }

    fprintf(stderr, "Generated RSA key/subkey:\n%s\n", key_grips);

    // We need to cleanup after ourselves!
    rnp_buffer_destroy(key_grips);
    key_grips = NULL;

    // We'll write the generated key to a file on disk.
    	// This instantiates an object representing that
	// file on disk...
    if (rnp_output_to_path(&keyfile, pubring) != RNP_SUCCESS) {
        fprintf(stderr, "failed to initialize %s writing.\n", pubring);
        goto finish;
    }

    // This will actually write the keys to disk.
    if (rnp_save_keys(ffi, "GPG", keyfile, RNP_LOAD_SAVE_PUBLIC_KEYS) != RNP_SUCCESS) {
        fprintf(stderr, "failed to save pubring\n");
        goto finish;
    }

    // Again, we're responsible for cleaning up any objects.
    rnp_output_destroy(keyfile);
    keyfile = NULL;

    // Create file output object and save secret keyring with generated keys.
    if (rnp_output_to_path(&keyfile, secring) != RNP_SUCCESS) {
        fprintf(stderr, "failed to initialize %s writing\n", secring);
        goto finish;
    }

    if (rnp_save_keys(ffi, "GPG", keyfile, RNP_LOAD_SAVE_SECRET_KEYS) != RNP_SUCCESS) {
        fprintf(stderr, "failed to save secring\n");
        goto finish;
    }

    rnp_output_destroy(keyfile);
    keyfile = NULL;

    // Signal everything went well to the caller.
    result = 0;
finish:
    rnp_buffer_destroy(key_grips);
    rnp_output_destroy(keyfile);
    rnp_ffi_destroy(ffi);
    return result;
}

int ffi_output_keys(char const* pubring, char const* secring) {
    rnp_ffi_t   ffi = NULL;
    rnp_input_t keyfile = NULL;
    int         result = 2;

    // Initialize FFI object
    if (rnp_ffi_create(&ffi, "GPG", "GPG") != RNP_SUCCESS) {
        return result;
    }

    // Load the publick keyring..
    if (rnp_input_from_path(&keyfile, pubring) != RNP_SUCCESS) {
        fprintf(stderr, "failed to open %s\n", pubring);
        goto finish;
    }

    // Actually, we may use 0 instead of RNP_LOAD_SAVE_PUBLIC_KEYS, to not check key types.
    if (rnp_load_keys(ffi, "GPG", keyfile, RNP_LOAD_SAVE_PUBLIC_KEYS) != RNP_SUCCESS) {
        fprintf(stderr, "failed to read %s\n", pubring);
        goto finish;
    }
    rnp_input_destroy(keyfile);
    keyfile = NULL;

    if (rnp_input_from_path(&keyfile, secring) != RNP_SUCCESS) {
        fprintf(stderr, "failed to open %s\n", secring);
        goto finish;
    }

    if (rnp_load_keys(ffi, "GPG", keyfile, RNP_LOAD_SAVE_SECRET_KEYS) != RNP_SUCCESS) {
        fprintf(stderr, "failed to read %s\n", secring);
        goto finish;
    }
    rnp_input_destroy(keyfile);
    keyfile = NULL;

    // Print armored keys to the stderr.
    if (!ffi_print_key(ffi, "sampleKey", false) || !ffi_print_key(ffi, "sampleKey", true)) {
        fprintf(stderr, "failed to print armored key(s)\n");
        goto finish;
    }

    // Write armored keys to the files, named key-<keyid>-pub.asc/named key-<keyid>-sec.asc.
    // if (!ffi_export_key(ffi, "sampleKey", false) || !ffi_export_key(ffi, "sampleKey", true)) {
    //    fprintf(stderr, "failed to write armored key(s) to file\n");
    //    goto finish;
    // }

    result = 0;
finish:
    rnp_input_destroy(keyfile);
    rnp_ffi_destroy(ffi);
    return result;
}
