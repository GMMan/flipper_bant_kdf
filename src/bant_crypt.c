#include <furi.h>
#include <flipper_format/flipper_format.h>
#include <storage/storage.h>

#include <mbedtls/md.h>
#include <mbedtls/error.h>

#include "bant_crypt.h"

#define MCHECK(expr) furi_check((expr) == 0)

#define TAG "BantCrypt"

#define BANT_CRYPT_SEEDS_PATH    EXT_PATH("nfc/assets/bant_seeds.nfc")
#define BANT_CRYPT_SEEDS_HEADER  "Bandai BANT seeds"
#define BANT_CRYPT_SEEDS_VERSION (2)

static size_t bant_crypt_get_string_len(FuriString* str) {
    size_t len = furi_string_size(str);
    if(furi_string_get_char(str, len - 1) == '\n') --len;
    return len;
}

void bant_crypt_derive_key(const uint8_t* uid, BantCryptSeed* seed, BantCryptKey* key) {
    mbedtls_md_context_t hmac;
    uint8_t hash[32];

    mbedtls_md_init(&hmac);
    MCHECK(mbedtls_md_setup(&hmac, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1));

    // Calculate HMAC for UID with first key
    MCHECK(mbedtls_md_hmac_starts(
        &hmac,
        (unsigned char*)furi_string_get_cstr(seed->hmac_key_a),
        bant_crypt_get_string_len(seed->hmac_key_a)));
    MCHECK(mbedtls_md_hmac_update(&hmac, uid, 7));
    MCHECK(mbedtls_md_hmac_finish(&hmac, hash));

    // Scramble the HMAC
    for(size_t i = 0; i < sizeof(hash); ++i) {
        hash[i] = seed->scramble_map[hash[i] & 0xf] |
                  (seed->scramble_map[(hash[i] >> 4) & 0xf] << 4);
    }

    // Calculate next HMAC with second key
    MCHECK(mbedtls_md_hmac_starts(
        &hmac,
        (unsigned char*)furi_string_get_cstr(seed->hmac_key_b),
        bant_crypt_get_string_len(seed->hmac_key_b)));
    MCHECK(mbedtls_md_hmac_update(&hmac, hash, sizeof(hash)));
    MCHECK(mbedtls_md_hmac_finish(&hmac, hash));

    mbedtls_md_free(&hmac);

    // Copy out results
    memcpy(key->key, hash, sizeof(key->key));
    memcpy(key->pwd, &hash[sizeof(hash) - sizeof(key->pwd)], sizeof(key->pwd));

    // Create IV
    memcpy(key->iv, hash, sizeof(key->iv) - 1);
    for(size_t i = 0; i < 8; ++i) {
        key->iv[i] ^= hash[sizeof(hash) - 8 + i];
    }
    for(size_t i = 0; i < 7; ++i) {
        key->iv[8 + i] ^= uid[i];
    }
    key->iv[sizeof(key->iv) - 1] = 0;
}

BantCryptSeed* bant_crypt_seed_alloc() {
    BantCryptSeed* seed = malloc(sizeof(BantCryptSeed));
    if(!seed) return NULL;
    seed->name = furi_string_alloc();
    seed->hmac_key_a = furi_string_alloc();
    seed->hmac_key_b = furi_string_alloc();
    memset(seed->scramble_map, 0, sizeof(seed->scramble_map));
    return seed;
}

void bant_crypt_seed_free(BantCryptSeed* seed) {
    furi_string_free(seed->name);
    furi_string_free(seed->hmac_key_a);
    furi_string_free(seed->hmac_key_b);
    free(seed);
}

void bant_crypt_seed_copy(BantCryptSeed* dst, BantCryptSeed* src) {
    furi_string_set(dst->name, src->name);
    furi_string_set(dst->hmac_key_a, src->hmac_key_a);
    furi_string_set(dst->hmac_key_b, src->hmac_key_b);
    memcpy(dst->scramble_map, src->scramble_map, sizeof(dst->scramble_map));
}

bool bant_crypt_load_seeds(BantCryptSeed*** seeds, size_t* count) {
    bool parsed = false;
    Storage* storage = furi_record_open(RECORD_STORAGE);
    FlipperFormat* file = flipper_format_file_alloc(storage);
    FuriString* temp_str = furi_string_alloc();

    *seeds = NULL;
    *count = 0;

    do {
        if(!flipper_format_file_open_existing(file, BANT_CRYPT_SEEDS_PATH)) break;

        // Check header and version
        uint32_t version;
        if(!flipper_format_read_header(file, temp_str, &version)) break;
        if(furi_string_cmp_str(temp_str, BANT_CRYPT_SEEDS_HEADER) ||
           version != BANT_CRYPT_SEEDS_VERSION)
            break;

        // Allocate array of seeds
        if(!flipper_format_read_uint32(file, "Count", (uint32_t*)count, 1)) break;
        *seeds = calloc(*count, sizeof(BantCryptSeed*));
        if(!(*seeds)) break;

        // Read each seed
        for(size_t i = 0; i < *count; ++i) {
            BantCryptSeed* curr = bant_crypt_seed_alloc();
            if(!curr) break;

            furi_string_printf(temp_str, "Name %d", i);
            if(!flipper_format_read_string(file, furi_string_get_cstr(temp_str), curr->name))
                break;
            furi_string_printf(temp_str, "Item ID %d", i);
            uint32_t temp_uint;
            if(!flipper_format_read_uint32(file, furi_string_get_cstr(temp_str), &temp_uint, 1))
                break;
            curr->item_id = temp_uint;
            furi_string_printf(temp_str, "HMAC key A %d", i);
            if(!flipper_format_read_string(file, furi_string_get_cstr(temp_str), curr->hmac_key_a))
                break;
            furi_string_printf(temp_str, "HMAC key B %d", i);
            if(!flipper_format_read_string(file, furi_string_get_cstr(temp_str), curr->hmac_key_b))
                break;
            furi_string_printf(temp_str, "Scramble map %d", i);
            if(!flipper_format_read_hex(
                   file,
                   furi_string_get_cstr(temp_str),
                   curr->scramble_map,
                   sizeof(curr->scramble_map)))
                break;

            (*seeds)[i] = curr;
        }

        parsed = true;
    } while(false);

    if(!parsed && *seeds) {
        for(size_t i = 0; i < *count; ++i) {
            if((*seeds)[i]) bant_crypt_seed_free((*seeds)[i]);
        }
        free(*seeds);
        *seeds = NULL;
        *count = 0;
    }

    furi_string_free(temp_str);
    flipper_format_free(file);
    furi_record_close(RECORD_STORAGE);
    return parsed;
}
