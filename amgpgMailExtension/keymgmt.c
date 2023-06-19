#include "amgpg_rnp.h"

void amgpg_print_n_keys(rnp_ffi_t ffi) {
    size_t npub, nsec;
    rnp_get_public_key_count(ffi, &npub);
    rnp_get_secret_key_count(ffi, &nsec);
    fprintf(stderr, "loaded %lu public keys and %lu private keys.\n", npub, nsec);
}

rnp_result_t amgpg_key_is(const char* pubring, const char* secring, const char* email, bool secret) {
    rnp_ffi_t        ffi = NULL;
    rnp_key_handle_t key = NULL;
    rnp_result_t     ret = RNP_ERROR_GENERIC;
    bool             is = false;

    // Initialize FFI object
    if ((ret = rnp_ffi_create(&ffi, PUBTYPE, SECTYPE)) != RNP_SUCCESS)
        return ret;

    if ((ret = load_keys(ffi, pubring, secring)) != RNP_SUCCESS) {
        rnp_ffi_destroy(ffi);
        return ret;
    }

    if ((ret = amgpg_load_key_by_email(ffi, email, &key)) != RNP_SUCCESS)
        goto finish;
    
    if (secret) {
        if ((ret = rnp_key_have_secret(key, &is)) != RNP_SUCCESS)
            goto finish;
    } else {
        if ((ret = rnp_key_have_public(key, &is)) != RNP_SUCCESS)
            goto finish;
    }

finish:
    rnp_ffi_destroy(ffi);
    rnp_key_handle_destroy(key);
    return is ? RNP_SUCCESS : RNP_ERROR_KEY_NOT_FOUND;
}

rnp_result_t amgpg_load_key_by_email(rnp_ffi_t ffi, const char* email, rnp_key_handle_t* key) {
    rnp_identifier_iterator_t it = NULL;
    const char* id = NULL;
    int ret;

    if (rnp_identifier_iterator_create(ffi, &it, "userid") != RNP_SUCCESS)
        return false;

    while ((ret = rnp_identifier_iterator_next(it, &id)) == RNP_SUCCESS) {
        if (!id)
            break;

        if (strstr(id, email)) {
            if ((ret = rnp_locate_key(ffi, "userid", id, key)) != RNP_SUCCESS)
                goto finish;
        }
    }
    if (!key)
        ret = RNP_ERROR_KEY_NOT_FOUND;
finish:
    rnp_identifier_iterator_destroy(it);
    return ret;
}

rnp_result_t amgpg_print_keys(rnp_ffi_t ffi, const char* id_type, bool secret) {
    rnp_identifier_iterator_t it = NULL;
    const char* id = NULL;
    int ret;

    if (rnp_identifier_iterator_create(ffi, &it, id_type) != RNP_SUCCESS)
        return false;

    while ((ret = rnp_identifier_iterator_next(it, &id)) == RNP_SUCCESS) {
        if (!id)
            break;

        fprintf(stderr, "printing key identified by %s: '%s'\n", id_type, id);

        if (!amgpg_print_key(ffi, id_type, id, secret))
            break;
    }

    return rnp_identifier_iterator_destroy(it);
}

rnp_result_t amgpg_print_key(rnp_ffi_t ffi, const char* id_type, const char *id, bool secret) {
    rnp_output_t     keydata = NULL;
    rnp_key_handle_t key = NULL;
    uint32_t         flags = RNP_KEY_EXPORT_ARMORED | RNP_KEY_EXPORT_SUBKEYS;
    uint8_t *        buf = NULL;
    size_t           buf_len = 0;
    rnp_result_t     ret = RNP_ERROR_GENERIC;

    // You may search for the key via userid, keyid, fingerprint, grip.
    if ((ret = rnp_locate_key(ffi, id_type, id, &key)) != RNP_SUCCESS)
        return ret;

    if (!key)
        return RNP_ERROR_KEY_NOT_FOUND;

    // Create in-memory output structure to later use buffer.
    if ((ret = rnp_output_to_memory(&keydata, 0)) != RNP_SUCCESS)
        goto finish;

    flags = flags | (secret ? RNP_KEY_EXPORT_SECRET : RNP_KEY_EXPORT_PUBLIC);
    if ((ret = rnp_key_export(key, keydata, flags)) != RNP_SUCCESS) {
        fprintf(stderr, "error exporting the key: %0x\n", ret);
        if (ret == RNP_ERROR_NO_SUITABLE_KEY || ret == RNP_ERROR_NOT_IMPLEMENTED)
            ret = RNP_SUCCESS;
        goto finish;
    }

    // Get key's contents from the output structure.
    if ((ret = rnp_output_memory_get_buf(keydata, &buf, &buf_len, false)) != RNP_SUCCESS)
        goto finish;

    fprintf(stderr, "%.*s", (int) buf_len, buf);

finish:
    rnp_key_handle_destroy(key);
    rnp_output_destroy(keydata);
    return ret;
}

rnp_result_t load_keys(rnp_ffi_t ffi, const char* pubring, const char* secring) {
    rnp_input_t  keyfile = NULL;
    rnp_result_t ret;

    // Load the public keyring.
    if ((ret = rnp_input_from_path(&keyfile, pubring)) != RNP_SUCCESS)
        return ret;

    // Actually, we may use 0 instead of RNP_LOAD_SAVE_PUBLIC_KEYS, to not check key types.
    if ((ret = rnp_load_keys(ffi, PUBTYPE, keyfile, RNP_LOAD_SAVE_PUBLIC_KEYS)) != RNP_SUCCESS)
        goto finish;

    rnp_input_destroy(keyfile);
    keyfile = NULL;

    if ((ret = rnp_input_from_path(&keyfile, secring)) != RNP_SUCCESS)
        return ret;

    ret = rnp_load_keys(ffi, SECTYPE, keyfile, RNP_LOAD_SAVE_SECRET_KEYS);

finish:
    rnp_input_destroy(keyfile);
    keyfile = NULL;

    return ret;
}

rnp_result_t amgpg_output_keys(const char* pubring, const char* secring) {
    rnp_ffi_t    ffi = NULL;
    rnp_result_t ret = RNP_ERROR_GENERIC;

    // Initialize FFI object
    if ((ret = rnp_ffi_create(&ffi, PUBTYPE, SECTYPE)) != RNP_SUCCESS)
        return ret;

    if ((ret = load_keys(ffi, pubring, secring)) != RNP_SUCCESS)
        goto finish;

    amgpg_print_n_keys(ffi);

    fprintf(stderr, "printing public keys...\n");
    amgpg_print_keys(ffi, "userid", false);

    fprintf(stderr, "printing secret keys...\n");
    amgpg_print_keys(ffi, "userid", true);

finish:
    rnp_ffi_destroy(ffi);
    return ret;
}
