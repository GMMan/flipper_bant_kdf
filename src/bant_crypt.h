#pragma once

#include <furi.h>

typedef struct BantCryptSeed {
    FuriString* name;
    FuriString* hmac_key_a;
    FuriString* hmac_key_b;
    uint8_t scramble_map[16];
    uint16_t item_id;
} BantCryptSeed;

typedef struct BantCryptKey {
    uint8_t key[16];
    uint8_t iv[16];
    uint8_t pwd[4];
} BantCryptKey;

void bant_crypt_derive_key(const uint8_t* uid, BantCryptSeed* seed, BantCryptKey* key);

BantCryptSeed* bant_crypt_seed_alloc();

void bant_crypt_seed_free(BantCryptSeed* seed);

void bant_crypt_seed_copy(BantCryptSeed* dst, BantCryptSeed* src);

bool bant_crypt_load_seeds(BantCryptSeed*** seeds, size_t* count);
