#include <stdlib.h>
#include <string.h>

#include "bant_crypt.h"

#include <flipper_application/flipper_application.h>
#include <bit_lib/bit_lib.h>

#include <nfc/nfc_device.h>
#include <nfc/protocols/mf_ultralight/mf_ultralight_poller_sync.h>
#include <nfc/plugins/supported_cards/nfc_supported_card_plugin.h>

#define TAG "BANT"

static const uint8_t BANT_MAGIC[] = {0x42, 0x41, 0x4e, 0x54};

static bool bant_select_key(const uint8_t* uid, uint8_t* product_info, uint8_t* password) {
    bool result = false;
    BantCryptSeed** seeds;
    size_t num_seeds;
    bool seeds_loaded = false;

    do {
        seeds_loaded = bant_crypt_load_seeds(&seeds, &num_seeds);
        if(!seeds_loaded) break;

        uint16_t item_id = bit_lib_bytes_to_num_be(product_info, 2);
        for(size_t i = 0; i < num_seeds; ++i) {
            if(item_id == seeds[i]->item_id) {
                BantCryptKey key;
                bant_crypt_derive_key(uid, seeds[i], &key);
                memcpy(password, key.pwd, sizeof(key.pwd));
                result = true;
                break;
            }
        }
    } while(false);

    if(seeds_loaded) {
        for(size_t i = 0; i < num_seeds; ++i) {
            bant_crypt_seed_free(seeds[i]);
        }
        free(seeds);
    }

    return result;
}

static bool bant_verify(Nfc* nfc) {
    bool verified = false;

    do {
        // Read BANT magic page
        MfUltralightPage page = {};
        MfUltralightError error = mf_ultralight_poller_sync_read_page(nfc, 4, &page);
        if(error != MfUltralightErrorNone) break;

        if(!memcmp(page.data, BANT_MAGIC, sizeof(BANT_MAGIC))) {
            verified = true;
        }
    } while(false);

    return verified;
}

static bool bant_read(Nfc* nfc, NfcDevice* device) {
    bool is_read = false;

    MfUltralightData* data = mf_ultralight_alloc();
    nfc_device_copy_data(device, NfcProtocolMfUltralight, data);

    const uint8_t* uid = mf_ultralight_get_uid(data, NULL);

    do {
        // Read product info page
        MfUltralightPage page = {};
        MfUltralightError error = mf_ultralight_poller_sync_read_page(nfc, 5, &page);
        if(error != MfUltralightErrorNone) break;

        // Setup auth
        MfUltralightPollerAuthContext auth_ctx = {};
        auth_ctx.skip_auth = false;
        if(!bant_select_key(uid, page.data, auth_ctx.password.data)) break;

        // Read the tag
        error = mf_ultralight_poller_sync_read_card(nfc, data, &auth_ctx);
        if(error != MfUltralightErrorNone) break;

        nfc_device_set_data(device, NfcProtocolMfUltralight, data);

        is_read = mf_ultralight_is_all_data_read(data);
    } while(false);

    mf_ultralight_free(data);

    return is_read;
}

static const NfcSupportedCardsPlugin bant_plugin = {
    .protocol = NfcProtocolMfUltralight,
    .verify = bant_verify,
    .read = bant_read,
    .parse = NULL,
};

static const FlipperAppPluginDescriptor bant_plugin_descriptor = {
    .appid = NFC_SUPPORTED_CARD_PLUGIN_APP_ID,
    .ep_api_version = NFC_SUPPORTED_CARD_PLUGIN_API_VERSION,
    .entry_point = &bant_plugin,
};

const FlipperAppPluginDescriptor* bant_plugin_ep(void) {
    return &bant_plugin_descriptor;
}
