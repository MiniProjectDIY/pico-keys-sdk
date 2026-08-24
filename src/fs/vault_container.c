/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "vault_container.h"

#include <stdlib.h>
#include <string.h>

#include "picokeys.h"
#include "button.h"
#include "random.h"
#include "serial.h"
#include "flash.h"
#include "led/led.h"
#if defined(ESP_PLATFORM)
#include "compat/esp_compat.h"
#else
#include "compat/board.h"
#endif
#include "mbedtls/chachapoly.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"

static const uint8_t vault_container_magic[4] = { 'K', 'V', 'W', '1' };
static const uint8_t vault_id_domain[] = "PicoKeys Vault ID v1";
static const uint8_t vault_enroll_info[] = "PicoKeys Vault enrollment v1";
static const uint8_t picokeys_vault_ca_der[] = {
    0x30, 0x82, 0x01, 0xEB, 0x30, 0x82, 0x01, 0x6B, 0xA0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x2B, 0x37, 0x6A, 0xC8, 0x98, 0x74, 0xE5, 0x0E, 0x80,
    0x1F, 0xB9, 0x61, 0xCD, 0x25, 0x80, 0x48, 0x17, 0xD6, 0x33, 0xA1, 0x30,
    0x05, 0x06, 0x03, 0x2B, 0x65, 0x71, 0x30, 0x3C, 0x31, 0x0B, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x45, 0x53, 0x31, 0x11, 0x30,
    0x0F, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x08, 0x50, 0x69, 0x63, 0x6F,
    0x4B, 0x65, 0x79, 0x73, 0x31, 0x1A, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0C, 0x11, 0x50, 0x69, 0x63, 0x6F, 0x4B, 0x65, 0x79, 0x73, 0x20,
    0x56, 0x61, 0x75, 0x6C, 0x74, 0x20, 0x43, 0x41, 0x30, 0x1E, 0x17, 0x0D,
    0x32, 0x36, 0x30, 0x38, 0x30, 0x35, 0x31, 0x36, 0x34, 0x34, 0x35, 0x36,
    0x5A, 0x17, 0x0D, 0x33, 0x36, 0x30, 0x38, 0x30, 0x32, 0x31, 0x36, 0x34,
    0x34, 0x35, 0x36, 0x5A, 0x30, 0x3C, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03,
    0x55, 0x04, 0x06, 0x13, 0x02, 0x45, 0x53, 0x31, 0x11, 0x30, 0x0F, 0x06,
    0x03, 0x55, 0x04, 0x0A, 0x0C, 0x08, 0x50, 0x69, 0x63, 0x6F, 0x4B, 0x65,
    0x79, 0x73, 0x31, 0x1A, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C,
    0x11, 0x50, 0x69, 0x63, 0x6F, 0x4B, 0x65, 0x79, 0x73, 0x20, 0x56, 0x61,
    0x75, 0x6C, 0x74, 0x20, 0x43, 0x41, 0x30, 0x43, 0x30, 0x05, 0x06, 0x03,
    0x2B, 0x65, 0x71, 0x03, 0x3A, 0x00, 0xE4, 0x0E, 0x8C, 0x62, 0xC6, 0xD3,
    0x6B, 0x06, 0xC4, 0x0A, 0x54, 0x40, 0x7C, 0x82, 0x1F, 0xDD, 0xAE, 0x93,
    0xF2, 0x88, 0x00, 0x9F, 0xDB, 0x10, 0x67, 0x9A, 0x32, 0x47, 0x62, 0xCE,
    0x92, 0x2A, 0xE2, 0x94, 0x2F, 0x40, 0xF4, 0xEC, 0x0A, 0xFE, 0x72, 0xA4,
    0x18, 0x5D, 0x20, 0x4D, 0x55, 0x97, 0x46, 0xE5, 0x94, 0x7D, 0x11, 0xF0,
    0x5C, 0xE6, 0x00, 0xA3, 0x66, 0x30, 0x64, 0x30, 0x1F, 0x06, 0x03, 0x55,
    0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xAE, 0xFB, 0xD5, 0x12,
    0x05, 0xBA, 0x61, 0xD7, 0x67, 0xE6, 0xAC, 0x78, 0x2E, 0x68, 0xD4, 0x22,
    0xFA, 0xC7, 0xDC, 0x26, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01,
    0x01, 0xFF, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x00,
    0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04,
    0x03, 0x02, 0x01, 0x06, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04,
    0x16, 0x04, 0x14, 0xAE, 0xFB, 0xD5, 0x12, 0x05, 0xBA, 0x61, 0xD7, 0x67,
    0xE6, 0xAC, 0x78, 0x2E, 0x68, 0xD4, 0x22, 0xFA, 0xC7, 0xDC, 0x26, 0x30,
    0x05, 0x06, 0x03, 0x2B, 0x65, 0x71, 0x03, 0x73, 0x00, 0x0B, 0xB4, 0x4F,
    0x45, 0x1C, 0x36, 0x77, 0xC1, 0x58, 0xDE, 0x39, 0xC0, 0x29, 0xA0, 0x7C,
    0x9F, 0x8F, 0x75, 0xC2, 0x9E, 0xAE, 0x12, 0x41, 0x00, 0xC8, 0xC9, 0x45,
    0xD1, 0xC0, 0xA6, 0x9A, 0x1D, 0xFA, 0x75, 0xE9, 0xB8, 0x82, 0x00, 0xE3,
    0x81, 0xCF, 0x74, 0x35, 0x59, 0x7F, 0x70, 0x06, 0x3A, 0xEC, 0xDF, 0x52,
    0x42, 0x53, 0x0D, 0xC3, 0x3B, 0x80, 0xF1, 0x1E, 0x3F, 0xC4, 0xAD, 0xC8,
    0xCA, 0x07, 0x4E, 0xBD, 0x5E, 0x35, 0xB7, 0x54, 0x63, 0x08, 0x43, 0x4B,
    0xB1, 0xCC, 0x7F, 0x1A, 0x45, 0x4C, 0xE1, 0x34, 0x57, 0x89, 0x57, 0xAA,
    0x08, 0xD5, 0xF6, 0x54, 0xC5, 0xE7, 0x49, 0xC7, 0xBA, 0xD7, 0x79, 0xAE,
    0xD6, 0x11, 0x05, 0x7A, 0xEF, 0x38, 0x97, 0x05, 0x96, 0x13, 0xC6, 0x95,
    0x01, 0x3A, 0x00,
};

static uint8_t vault_enroll_private[PICOKEYS_VAULT_X448_BYTES];
static uint8_t vault_enroll_public[PICOKEYS_VAULT_X448_BYTES];
static uint8_t vault_enroll_challenge[PICOKEYS_VAULT_ENROLL_CHALLENGE_BYTES];
static bool vault_enroll_active;
static bool vault_enroll_button_accepted;


bool picokeys_vault_container_valid(const uint8_t *data, size_t data_len, size_t record_size) {
    if (!data || record_size == 0 || data_len < PICOKEYS_VAULT_CONTAINER_HEADER_SIZE || memcmp(data, vault_container_magic, sizeof(vault_container_magic)) != 0 || data[4] != 1) {
        return false;
    }

    uint8_t count = data[5];
    size_t container_record_size = PICOKEYS_VAULT_CONTAINER_RECORD_PREFIX_SIZE + record_size;
    if (count == 0 || data_len != PICOKEYS_VAULT_CONTAINER_HEADER_SIZE + count * container_record_size) {
        return false;
    }

    for (uint8_t i = 0; i < count; i++) {
        size_t offset = PICOKEYS_VAULT_CONTAINER_HEADER_SIZE + i * container_record_size;
        for (uint8_t j = 0; j < i; j++) {
            size_t previous_offset = PICOKEYS_VAULT_CONTAINER_HEADER_SIZE + j * container_record_size;
            if (data[offset] == data[previous_offset]) {
                return false;
            }
        }
    }
    return true;
}

bool picokeys_vault_record_valid(const uint8_t *record, size_t record_len) {
    return record && record_len == PICOKEYS_VAULT_RECORD_SIZE && record[0] == PICOKEYS_VAULT_RECORD_FORMAT;
}

const uint8_t *picokeys_vault_find_record(const file_t *file, uint8_t app_id, size_t record_size) {
    if (!file || !file_has_data(file) || record_size == 0) {
        return NULL;
    }

    const uint8_t *data = file_get_data(file);
    size_t data_len = file_get_size(file);
    if (app_id == 0 && data_len == record_size) {
        return data;
    }
    if (!picokeys_vault_container_valid(data, data_len, record_size)) {
        return NULL;
    }

    uint8_t count = data[5];
    size_t container_record_size = PICOKEYS_VAULT_CONTAINER_RECORD_PREFIX_SIZE + record_size;
    for (uint8_t i = 0; i < count; i++) {
        size_t offset = PICOKEYS_VAULT_CONTAINER_HEADER_SIZE + i * container_record_size;
        if (data[offset] == app_id) {
            return data + offset + PICOKEYS_VAULT_CONTAINER_RECORD_PREFIX_SIZE;
        }
    }
    return NULL;
}

bool picokeys_vault_record_available(const file_t *file, uint8_t app_id) {
    const uint8_t *record = picokeys_vault_find_record(file, app_id, PICOKEYS_VAULT_RECORD_SIZE);
    return picokeys_vault_record_valid(record, PICOKEYS_VAULT_RECORD_SIZE);
}

int picokeys_vault_store_record(file_t *file, uint8_t app_id, const_byte_array_t record, uint8_t *scratch, size_t scratch_size) {
    if (!file || record.len == 0 || !record.data || !scratch || record.len > scratch_size) {
        return PICOKEYS_WRONG_DATA;
    }

    size_t container_record_size = PICOKEYS_VAULT_CONTAINER_RECORD_PREFIX_SIZE + record.len;
    size_t minimum_container_size = PICOKEYS_VAULT_CONTAINER_HEADER_SIZE + container_record_size;
    if (minimum_container_size > scratch_size) {
        return PICOKEYS_WRONG_LENGTH;
    }
    size_t container_len;
    if (!file_has_data(file)) {
        memcpy(scratch, vault_container_magic, sizeof(vault_container_magic));
        scratch[4] = 1;
        scratch[5] = 1;
        scratch[PICOKEYS_VAULT_CONTAINER_HEADER_SIZE] = app_id;
        memcpy(scratch + PICOKEYS_VAULT_CONTAINER_HEADER_SIZE + 1, record.data, record.len);
        container_len = PICOKEYS_VAULT_CONTAINER_HEADER_SIZE + container_record_size;
    }
    else {
        const uint8_t *data = file_get_data(file);
        size_t data_len = file_get_size(file);
        if (data_len == record.len) {
            memcpy(scratch, vault_container_magic, sizeof(vault_container_magic));
            scratch[4] = 1;
            scratch[5] = 1;
            scratch[PICOKEYS_VAULT_CONTAINER_HEADER_SIZE] = 0;
            memcpy(scratch + PICOKEYS_VAULT_CONTAINER_HEADER_SIZE + 1, data, data_len);
            container_len = PICOKEYS_VAULT_CONTAINER_HEADER_SIZE + container_record_size;
        }
        else if (picokeys_vault_container_valid(data, data_len, record.len)) {
            if (data_len > scratch_size || data_len + container_record_size > scratch_size) {
                return PICOKEYS_WRONG_LENGTH;
            }
            memcpy(scratch, data, data_len);
            container_len = data_len;
        }
        else {
            return PICOKEYS_WRONG_DATA;
        }
    }

    uint8_t count = scratch[5];
    for (uint8_t i = 0; i < count; i++) {
        size_t offset = PICOKEYS_VAULT_CONTAINER_HEADER_SIZE + i * container_record_size;
        if (scratch[offset] == app_id) {
            memcpy(scratch + offset + 1, record.data, record.len);
            return file_put_data(file, CONST_BYTE_ARRAY(scratch, container_len));
        }
    }
    if (count == UINT8_MAX) {
        return PICOKEYS_ERR_NO_MEMORY;
    }

    size_t offset = PICOKEYS_VAULT_CONTAINER_HEADER_SIZE + count * container_record_size;
    scratch[offset] = app_id;
    memcpy(scratch + offset + 1, record.data, record.len);
    scratch[5] = count + 1;
    container_len += container_record_size;
    return file_put_data(file, CONST_BYTE_ARRAY(scratch, container_len));
}

int picokeys_vault_wrap(const uint8_t wrapping_key[PICOKEYS_VAULT_KEY_SIZE], const uint8_t kvault[PICOKEYS_VAULT_KEY_SIZE], uint8_t record[PICOKEYS_VAULT_RECORD_SIZE]) {
    if (!wrapping_key || !kvault || !record) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    record[0] = PICOKEYS_VAULT_RECORD_FORMAT;
    return encrypt_with_aad(wrapping_key, CONST_BYTE_ARRAY(kvault, PICOKEYS_VAULT_KEY_SIZE), PICOKEYS_VAULT_RECORD_FORMAT, record + 1);
}

int picokeys_vault_unwrap(const uint8_t wrapping_key[PICOKEYS_VAULT_KEY_SIZE], const uint8_t record[PICOKEYS_VAULT_RECORD_SIZE], uint8_t kvault[PICOKEYS_VAULT_KEY_SIZE]) {
    if (!wrapping_key || !record || !kvault) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (record[0] != PICOKEYS_VAULT_RECORD_FORMAT) {
        return PICOKEYS_WRONG_DATA;
    }

    return decrypt_with_aad(wrapping_key, CONST_BYTE_ARRAY(record + 1, PICOKEYS_VAULT_RECORD_SIZE - 1), PICOKEYS_VAULT_RECORD_FORMAT, kvault);
}

int picokeys_vault_load_kvault(const file_t *file, uint8_t app_id, const uint8_t wrapping_key[PICOKEYS_VAULT_KEY_SIZE], uint8_t kvault[PICOKEYS_VAULT_KEY_SIZE]) {
    if (!file || !wrapping_key || !kvault) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    const uint8_t *record = picokeys_vault_find_record(file, app_id, PICOKEYS_VAULT_RECORD_SIZE);
    if (!record) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }

    return picokeys_vault_unwrap(wrapping_key, record, kvault);
}

int picokeys_vault_store_kvault(file_t *file, uint8_t app_id, const uint8_t wrapping_key[PICOKEYS_VAULT_KEY_SIZE], const uint8_t kvault[PICOKEYS_VAULT_KEY_SIZE]) {
    if (!file || !wrapping_key || !kvault) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    uint8_t record[PICOKEYS_VAULT_RECORD_SIZE] = { 0 };
    int ret = picokeys_vault_wrap(wrapping_key, kvault, record);
    if (ret == PICOKEYS_OK) {
        size_t container_size = PICOKEYS_VAULT_CONTAINER_HEADER_SIZE + PICOKEYS_VAULT_CONTAINER_RECORD_PREFIX_SIZE + PICOKEYS_VAULT_RECORD_SIZE;
        if (file_has_data(file)) {
            container_size = file_get_size(file) + PICOKEYS_VAULT_CONTAINER_RECORD_PREFIX_SIZE + PICOKEYS_VAULT_RECORD_SIZE;
        }
        uint8_t *container = malloc(container_size);
        if (!container) {
            ret = PICOKEYS_ERR_NO_MEMORY;
        }
        else {
            ret = picokeys_vault_store_record(file, app_id, CONST_BYTE_ARRAY(record, sizeof(record)), container, container_size);
            mbedtls_platform_zeroize(container, container_size);
            free(container);
        }
    }
    mbedtls_platform_zeroize(record, sizeof(record));
    return ret;
}

int picokeys_vault_layer_key(const uint8_t key[PICOKEYS_VAULT_KEY_SIZE], const uint8_t vault_id[PICOKEYS_VAULT_KEY_SIZE], const uint8_t credential_hash[PICOKEYS_VAULT_KEY_SIZE], uint8_t algorithm, uint8_t layer, uint8_t out[PICOKEYS_VAULT_KEY_SIZE]) {
    if (!key || !vault_id || !credential_hash || !out) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    uint8_t info[sizeof(vault_enroll_info) - 1 + PICOKEYS_VAULT_KEY_SIZE + 2];
    memcpy(info, vault_enroll_info, sizeof(vault_enroll_info) - 1);
    memcpy(info + sizeof(vault_enroll_info) - 1, credential_hash, PICOKEYS_VAULT_KEY_SIZE);
    info[sizeof(vault_enroll_info) - 1 + PICOKEYS_VAULT_KEY_SIZE] = algorithm;
    info[sizeof(vault_enroll_info) - 1 + PICOKEYS_VAULT_KEY_SIZE + 1] = layer;
    int ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), vault_id, PICOKEYS_VAULT_KEY_SIZE, key, PICOKEYS_VAULT_KEY_SIZE, info, sizeof(info), out, PICOKEYS_VAULT_KEY_SIZE);
    mbedtls_platform_zeroize(info, sizeof(info));
    return ret == 0 ? PICOKEYS_OK : PICOKEYS_EXEC_ERROR;
}

int picokeys_vault_encrypt_layer(uint8_t algorithm, const uint8_t key[PICOKEYS_VAULT_KEY_SIZE], const uint8_t nonce[PICOKEYS_VAULT_BLOB_NONCE_SIZE], const uint8_t *aad, size_t aad_len, const uint8_t *input, size_t input_len, uint8_t *output, uint8_t tag[PICOKEYS_VAULT_BLOB_TAG_SIZE]) {
    if (!key || !nonce || (aad_len > 0 && !aad) || (input_len > 0 && (!input || !output)) || !tag) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    int ret = -1;
    if (algorithm == PICOKEYS_VAULT_ALGORITHM_CHACHAPOLY) {
        mbedtls_chachapoly_context chatx;
        mbedtls_chachapoly_init(&chatx);
        ret = mbedtls_chachapoly_setkey(&chatx, key);
        if (ret == 0) {
            ret = mbedtls_chachapoly_encrypt_and_tag(&chatx, input_len, nonce, aad, aad_len, input, output, tag);
        }
        mbedtls_chachapoly_free(&chatx);
    }
    else if (algorithm == PICOKEYS_VAULT_ALGORITHM_AESGCM) {
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init(&gcm);
        ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
        if (ret == 0) {
            ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, input_len, nonce, PICOKEYS_VAULT_BLOB_NONCE_SIZE, aad, aad_len, input, output, PICOKEYS_VAULT_BLOB_TAG_SIZE, tag);
        }
        mbedtls_gcm_free(&gcm);
    }
    return ret == 0 ? PICOKEYS_OK : PICOKEYS_EXEC_ERROR;
}

int picokeys_vault_decrypt_layer(uint8_t algorithm, const uint8_t key[PICOKEYS_VAULT_KEY_SIZE], const uint8_t nonce[PICOKEYS_VAULT_BLOB_NONCE_SIZE], const uint8_t *aad, size_t aad_len, const uint8_t *input, size_t input_len, const uint8_t tag[PICOKEYS_VAULT_BLOB_TAG_SIZE], uint8_t *output) {
    if (!key || !nonce || (aad_len > 0 && !aad) || (input_len > 0 && (!input || !output)) || !tag) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    int ret = -1;
    if (algorithm == PICOKEYS_VAULT_ALGORITHM_CHACHAPOLY) {
        mbedtls_chachapoly_context chatx;
        mbedtls_chachapoly_init(&chatx);
        ret = mbedtls_chachapoly_setkey(&chatx, key);
        if (ret == 0) {
            ret = mbedtls_chachapoly_auth_decrypt(&chatx, input_len, nonce, aad, aad_len, tag, input, output);
        }
        mbedtls_chachapoly_free(&chatx);
    }
    else if (algorithm == PICOKEYS_VAULT_ALGORITHM_AESGCM) {
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init(&gcm);
        ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
        if (ret == 0) {
            ret = mbedtls_gcm_auth_decrypt(&gcm, input_len, nonce, PICOKEYS_VAULT_BLOB_NONCE_SIZE, aad, aad_len, tag, PICOKEYS_VAULT_BLOB_TAG_SIZE, input, output);
        }
        mbedtls_gcm_free(&gcm);
    }
    return ret == 0 ? PICOKEYS_OK : PICOKEYS_VERIFICATION_FAILED;
}

int picokeys_vault_hash_kvault(const uint8_t kvault[PICOKEYS_VAULT_KEY_SIZE], uint8_t vault_id[PICOKEYS_VAULT_KEY_SIZE]) {
    if (!kvault || !vault_id) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    uint8_t input[sizeof(vault_id_domain) - 1 + PICOKEYS_VAULT_KEY_SIZE] = { 0 };
    memcpy(input, vault_id_domain, sizeof(vault_id_domain) - 1);
    memcpy(input + sizeof(vault_id_domain) - 1, kvault, PICOKEYS_VAULT_KEY_SIZE);
    hash256(CONST_BYTE_ARRAY(input, sizeof(input)), vault_id);
    mbedtls_platform_zeroize(input, sizeof(input));
    return PICOKEYS_OK;
}

int picokeys_vault_clear_wrappers(file_t *file, uint8_t preserve_app_id) {
    if (!file || !file_has_data(file)) {
        return PICOKEYS_OK;
    }

    const uint8_t *data = file_get_data(file);
    size_t data_len = file_get_size(file);
    if (picokeys_vault_record_valid(data, data_len)) {
        return PICOKEYS_OK;
    }
    if (!picokeys_vault_container_valid(data, data_len, PICOKEYS_VAULT_RECORD_SIZE)) {
        return PICOKEYS_WRONG_DATA;
    }

    const uint8_t *record = picokeys_vault_find_record(file, preserve_app_id, PICOKEYS_VAULT_RECORD_SIZE);
    if (!record) {
        return flash_clear_file(file);
    }

    uint8_t legacy_record[PICOKEYS_VAULT_RECORD_SIZE] = { 0 };
    memcpy(legacy_record, record, sizeof(legacy_record));
    int ret = file_put_data(file, CONST_BYTE_ARRAY(legacy_record, sizeof(legacy_record)));
    mbedtls_platform_zeroize(legacy_record, sizeof(legacy_record));
    return ret;
}

int picokeys_vault_x448_generate(uint8_t private_key[PICOKEYS_VAULT_X448_BYTES], uint8_t public_key[PICOKEYS_VAULT_X448_BYTES]) {
    if (!private_key || !public_key) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    mbedtls_ecp_keypair key;
    size_t private_len = 0;
    size_t public_len = 0;
    mbedtls_ecp_keypair_init(&key);
    int ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_CURVE448, &key, random_fill_iterator, NULL);
    if (ret == 0) {
        ret = mbedtls_ecp_write_key_ext(&key, &private_len, private_key, PICOKEYS_VAULT_X448_BYTES);
    }
    if (ret == 0) {
        ret = mbedtls_ecp_point_write_binary(&key.MBEDTLS_PRIVATE(grp), &key.MBEDTLS_PRIVATE(Q), MBEDTLS_ECP_PF_UNCOMPRESSED, &public_len, public_key, PICOKEYS_VAULT_X448_BYTES);
    }
    mbedtls_ecp_keypair_free(&key);
    if (ret != 0) {
        return PICOKEYS_EXEC_ERROR;
    }
    return private_len == PICOKEYS_VAULT_X448_BYTES && public_len == PICOKEYS_VAULT_X448_BYTES ? PICOKEYS_OK : PICOKEYS_WRONG_LENGTH;
}

int picokeys_vault_x448_shared(const uint8_t private_key[PICOKEYS_VAULT_X448_BYTES], const uint8_t peer_public[PICOKEYS_VAULT_X448_BYTES], uint8_t shared[PICOKEYS_VAULT_X448_BYTES]) {
    if (!private_key || !peer_public || !shared) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    mbedtls_ecdh_context ecdh;
    mbedtls_ecp_keypair ours;
    mbedtls_ecp_keypair theirs;
    size_t shared_len = 0;
    mbedtls_ecdh_init(&ecdh);
    mbedtls_ecp_keypair_init(&ours);
    mbedtls_ecp_keypair_init(&theirs);
    int ret = mbedtls_ecp_group_load(&ours.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_CURVE448);
    if (ret == 0) {
        ret = mbedtls_ecp_group_load(&theirs.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_CURVE448);
    }
    if (ret == 0) {
        ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_CURVE448, &ours, private_key, PICOKEYS_VAULT_X448_BYTES);
    }
    if (ret == 0) {
        ret = mbedtls_ecp_point_read_binary(&theirs.MBEDTLS_PRIVATE(grp), &theirs.MBEDTLS_PRIVATE(Q), peer_public, PICOKEYS_VAULT_X448_BYTES);
    }
    if (ret == 0) {
        ret = mbedtls_ecdh_setup(&ecdh, MBEDTLS_ECP_DP_CURVE448);
    }
    if (ret == 0) {
        ret = mbedtls_ecdh_get_params(&ecdh, &ours, MBEDTLS_ECDH_OURS);
    }
    if (ret == 0) {
        ret = mbedtls_ecdh_get_params(&ecdh, &theirs, MBEDTLS_ECDH_THEIRS);
    }
    if (ret == 0) {
        ret = mbedtls_ecdh_calc_secret(&ecdh, &shared_len, shared, PICOKEYS_VAULT_X448_BYTES, random_fill_iterator, NULL);
    }
    mbedtls_ecdh_free(&ecdh);
    mbedtls_ecp_keypair_free(&ours);
    mbedtls_ecp_keypair_free(&theirs);
    if (ret != 0) {
        return PICOKEYS_EXEC_ERROR;
    }
    return shared_len == PICOKEYS_VAULT_X448_BYTES ? PICOKEYS_OK : PICOKEYS_WRONG_LENGTH;
}

bool picokeys_vault_enrollment_active(void) {
    return vault_enroll_active;
}

#ifndef ENABLE_EMULATION
static bool vault_enrollment_window_open(void) {
    return board_millis() < PICOKEYS_VAULT_ENROLL_WINDOW_MS;
}
#endif

bool picokeys_vault_enrollment_button_ready(void) {
#ifdef ENABLE_EMULATION
    vault_enroll_button_accepted = true;
    return true;
#else
    if (!vault_enrollment_window_open() && !vault_enroll_active) {
        vault_enroll_button_accepted = false;
        button_pressed_duration = 0;
        led_set_mode(MODE_MOUNTED);
        return false;
    }
    if (button_pressed_duration >= PICOKEYS_VAULT_ENROLL_HOLD_MS) {
        if (!vault_enroll_button_accepted) {
            led_set_mode(MODE_BUTTON);
        }
        vault_enroll_button_accepted = true;
    }
    return vault_enroll_button_accepted;
#endif
}

int picokeys_vault_enrollment_start(uint8_t public_key[PICOKEYS_VAULT_X448_BYTES], uint8_t challenge[PICOKEYS_VAULT_ENROLL_CHALLENGE_BYTES]) {
    if (!public_key || !challenge) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    picokeys_vault_enrollment_clear();
    int ret = picokeys_vault_x448_generate(vault_enroll_private, public_key);
    if (ret == PICOKEYS_OK) {
        memcpy(vault_enroll_public, public_key, PICOKEYS_VAULT_X448_BYTES);
        random_fill_buffer(BYTE_ARRAY(vault_enroll_challenge, sizeof(vault_enroll_challenge)));
        memcpy(challenge, vault_enroll_challenge, sizeof(vault_enroll_challenge));
        vault_enroll_active = true;
#ifndef ENABLE_EMULATION
        led_set_mode(MODE_BUTTON);
#endif
    }
    return ret;
}

void picokeys_vault_enrollment_clear(void) {
    mbedtls_platform_zeroize(vault_enroll_private, sizeof(vault_enroll_private));
    mbedtls_platform_zeroize(vault_enroll_challenge, sizeof(vault_enroll_challenge));
    mbedtls_platform_zeroize(vault_enroll_public, sizeof(vault_enroll_public));
    vault_enroll_active = false;
    vault_enroll_button_accepted = false;
}

void picokeys_vault_enrollment_reset(void) {
    picokeys_vault_enrollment_clear();
#ifndef ENABLE_EMULATION
    button_pressed_duration = 0;
    led_set_mode(MODE_MOUNTED);
#endif
}

static int vault_enrollment_validate_certificate(mbedtls_x509_crt *certificate) {
    if (!certificate) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    mbedtls_x509_crt ca;
    uint32_t flags = 0;
    mbedtls_x509_crt_init(&ca);
    int ret = mbedtls_x509_crt_parse(&ca, picokeys_vault_ca_der, sizeof(picokeys_vault_ca_der));
    if (ret == 0) {
        ret = mbedtls_x509_crt_verify(certificate, &ca, NULL, NULL, &flags, NULL, NULL);
    }
    mbedtls_x509_crt_free(&ca);
    return ret != 0 ? PICOKEYS_EXEC_ERROR : (flags == 0 ? PICOKEYS_OK : PICOKEYS_VERIFICATION_FAILED);
}

static int vault_enrollment_validate_serial(mbedtls_x509_crt *certificate) {
    if (!certificate || !certificate->subject_alt_names.next) {
        return PICOKEYS_VERIFICATION_FAILED;
    }

    size_t serial_len = strlen(pico_serial_str);
    for (mbedtls_x509_sequence *entry = certificate->subject_alt_names.next; entry; entry = entry->next) {
        mbedtls_x509_subject_alternative_name san = {0};
        int ret = mbedtls_x509_parse_subject_alt_name(&entry->buf, &san);
        if (ret == 0 && (san.type == MBEDTLS_X509_SAN_DNS_NAME || san.type == MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER) && san.san.unstructured_name.len == serial_len && memcmp(san.san.unstructured_name.p, pico_serial_str, serial_len) == 0) {
            mbedtls_x509_free_subject_alt_name(&san);
            return PICOKEYS_OK;
        }
        mbedtls_x509_free_subject_alt_name(&san);
    }
    return PICOKEYS_VERIFICATION_FAILED;
}

static int vault_enrollment_certificate_public(mbedtls_x509_crt *certificate, uint8_t public_key[PICOKEYS_VAULT_X448_BYTES]) {
    if (!certificate || !public_key || (mbedtls_pk_get_type(&certificate->pk) != MBEDTLS_PK_ECKEY && mbedtls_pk_get_type(&certificate->pk) != MBEDTLS_PK_ECKEY_DH)) {
        return PICOKEYS_WRONG_DATA;
    }

    mbedtls_ecp_keypair *key = mbedtls_pk_ec(certificate->pk);
    if (!key || key->MBEDTLS_PRIVATE(grp).id != MBEDTLS_ECP_DP_CURVE448) {
        return PICOKEYS_WRONG_DATA;
    }

    size_t public_len = 0;
    int ret = mbedtls_ecp_point_write_binary(&key->MBEDTLS_PRIVATE(grp), &key->MBEDTLS_PRIVATE(Q), MBEDTLS_ECP_PF_UNCOMPRESSED, &public_len, public_key, PICOKEYS_VAULT_X448_BYTES);
    return ret == 0 && public_len == PICOKEYS_VAULT_X448_BYTES ? PICOKEYS_OK : PICOKEYS_WRONG_DATA;
}

int picokeys_vault_enrollment_finish(const uint8_t *packet, size_t packet_len, file_t *file, uint8_t app_id, const uint8_t wrapping_key[PICOKEYS_VAULT_KEY_SIZE], uint8_t *metadata, size_t metadata_capacity, size_t *metadata_len) {
    if (!picokeys_vault_enrollment_active() || !packet || !file || !wrapping_key || !metadata_len || (metadata_capacity > 0 && !metadata) || packet_len < PICOKEYS_VAULT_ENROLL_MIN_PACKET_LEN) {
        picokeys_vault_enrollment_reset();
        return PICOKEYS_WRONG_LENGTH;
    }

    *metadata_len = 0;
    uint16_t certificate_len = ((uint16_t)packet[0] << 8) | packet[1];
    size_t certificate_offset = 2;
    size_t encrypted_offset = certificate_offset + certificate_len;
    if (certificate_len == 0 || certificate_len > PICOKEYS_VAULT_ENROLL_CERT_MAX || encrypted_offset > packet_len || packet_len < encrypted_offset + 12u + 16u + PICOKEYS_VAULT_KEY_SIZE) {
        picokeys_vault_enrollment_reset();
        return PICOKEYS_WRONG_LENGTH;
    }

    size_t encrypted_len = packet_len - encrypted_offset - 12u;
    if (encrypted_len < PICOKEYS_VAULT_KEY_SIZE + 16u || encrypted_len > PICOKEYS_VAULT_ENROLL_PLAIN_MAX + 16u) {
        picokeys_vault_enrollment_reset();
        return PICOKEYS_WRONG_LENGTH;
    }

    mbedtls_x509_crt certificate;
    mbedtls_x509_crt_init(&certificate);
    int ret = mbedtls_x509_crt_parse(&certificate, packet + certificate_offset, certificate_len);
    if (ret == 0) {
        ret = vault_enrollment_validate_certificate(&certificate);
    }
    if (ret == PICOKEYS_OK) {
        ret = vault_enrollment_validate_serial(&certificate);
    }

    uint8_t certificate_public[PICOKEYS_VAULT_X448_BYTES] = { 0 };
    if (ret == PICOKEYS_OK) {
        ret = vault_enrollment_certificate_public(&certificate, certificate_public);
    }
    mbedtls_x509_crt_free(&certificate);
    if (ret != PICOKEYS_OK) {
        mbedtls_platform_zeroize(certificate_public, sizeof(certificate_public));
        picokeys_vault_enrollment_reset();
        return PICOKEYS_VERIFICATION_FAILED;
    }

    uint8_t shared[PICOKEYS_VAULT_X448_BYTES] = { 0 };
    uint8_t session_key[PICOKEYS_VAULT_KEY_SIZE] = { 0 };
    uint8_t info[sizeof(vault_enroll_info) - 1 + PICOKEYS_VAULT_ENROLL_CHALLENGE_BYTES + PICOKEYS_VAULT_X448_BYTES * 2] = { 0 };
    memcpy(info, vault_enroll_info, sizeof(vault_enroll_info) - 1);
    memcpy(info + sizeof(vault_enroll_info) - 1, vault_enroll_challenge, PICOKEYS_VAULT_ENROLL_CHALLENGE_BYTES);
    memcpy(info + sizeof(vault_enroll_info) - 1 + PICOKEYS_VAULT_ENROLL_CHALLENGE_BYTES, certificate_public, PICOKEYS_VAULT_X448_BYTES);
    memcpy(info + sizeof(vault_enroll_info) - 1 + PICOKEYS_VAULT_ENROLL_CHALLENGE_BYTES + PICOKEYS_VAULT_X448_BYTES, vault_enroll_public, PICOKEYS_VAULT_X448_BYTES);

    ret = picokeys_vault_x448_shared(vault_enroll_private, certificate_public, shared);
    if (ret == PICOKEYS_OK) {
        ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0, shared, sizeof(shared), info, sizeof(info), session_key, sizeof(session_key));
    }

    uint8_t kvault[PICOKEYS_VAULT_KEY_SIZE] = { 0 };
    uint8_t enrollment_plain[PICOKEYS_VAULT_ENROLL_PLAIN_MAX] = { 0 };
    size_t plain_len = encrypted_len - 16u;
    if (ret == PICOKEYS_OK) {
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init(&gcm);
        ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, session_key, 256);
        if (ret == 0) {
            ret = mbedtls_gcm_auth_decrypt(&gcm, plain_len, packet + encrypted_offset + 12u, 12u, info, sizeof(info), packet + encrypted_offset + 12u + plain_len, 16u, packet + encrypted_offset + 12u, enrollment_plain);
        }
        mbedtls_gcm_free(&gcm);
    }

    size_t plain_metadata_len = 0;
    if (ret == 0 && plain_len == PICOKEYS_VAULT_KEY_SIZE) {
        memcpy(kvault, enrollment_plain, PICOKEYS_VAULT_KEY_SIZE);
    }
    else if (ret == 0 && plain_len >= PICOKEYS_VAULT_KEY_SIZE + 1u && enrollment_plain[PICOKEYS_VAULT_KEY_SIZE] <= 64u && plain_len == PICOKEYS_VAULT_KEY_SIZE + 1u + enrollment_plain[PICOKEYS_VAULT_KEY_SIZE]) {
        memcpy(kvault, enrollment_plain, PICOKEYS_VAULT_KEY_SIZE);
        plain_metadata_len = enrollment_plain[PICOKEYS_VAULT_KEY_SIZE];
        if (plain_metadata_len > metadata_capacity) {
            ret = PICOKEYS_ERR_NO_MEMORY;
        }
        else if (plain_metadata_len > 0 && metadata) {
            memcpy(metadata, enrollment_plain + PICOKEYS_VAULT_KEY_SIZE + 1u, plain_metadata_len);
        }
    }
    else if (ret == 0) {
        ret = PICOKEYS_WRONG_LENGTH;
    }

    if (ret == PICOKEYS_OK) {
        ret = picokeys_vault_store_kvault(file, app_id, wrapping_key, kvault);
    }
    if (ret == PICOKEYS_OK && !flash_commit_sync(5000)) {
        ret = PICOKEYS_ERR_MEMORY_FATAL;
    }
    if (ret == PICOKEYS_OK) {
        *metadata_len = plain_metadata_len;
    }

    mbedtls_platform_zeroize(shared, sizeof(shared));
    mbedtls_platform_zeroize(session_key, sizeof(session_key));
    mbedtls_platform_zeroize(info, sizeof(info));
    mbedtls_platform_zeroize(certificate_public, sizeof(certificate_public));
    mbedtls_platform_zeroize(kvault, sizeof(kvault));
    mbedtls_platform_zeroize(enrollment_plain, sizeof(enrollment_plain));
    picokeys_vault_enrollment_reset();
    return ret;
}

static int vault_remove_record(file_t *file, uint8_t app_id) {
    if (!file || !file_has_data(file)) {
        return PICOKEYS_OK;
    }

    const uint8_t *data = file_get_data(file);
    size_t data_len = file_get_size(file);
    if (picokeys_vault_record_valid(data, data_len)) {
        return app_id == 0 ? flash_clear_file(file) : PICOKEYS_OK;
    }
    if (!picokeys_vault_container_valid(data, data_len, PICOKEYS_VAULT_RECORD_SIZE)) {
        return PICOKEYS_WRONG_DATA;
    }

    uint8_t count = data[5];
    size_t record_size = PICOKEYS_VAULT_CONTAINER_RECORD_PREFIX_SIZE + PICOKEYS_VAULT_RECORD_SIZE;
    size_t remove_index = count;
    for (uint8_t i = 0; i < count; i++) {
        if (data[PICOKEYS_VAULT_CONTAINER_HEADER_SIZE + i * record_size] == app_id) {
            remove_index = i;
            break;
        }
    }
    if (remove_index == count) {
        return PICOKEYS_OK;
    }
    if (count == 1) {
        return flash_clear_file(file);
    }

    uint8_t *updated = malloc(data_len);
    if (!updated) {
        return PICOKEYS_ERR_NO_MEMORY;
    }
    memcpy(updated, data, PICOKEYS_VAULT_CONTAINER_HEADER_SIZE);
    updated[5] = count - 1;
    size_t output_offset = PICOKEYS_VAULT_CONTAINER_HEADER_SIZE;
    for (uint8_t i = 0; i < count; i++) {
        if (i != remove_index) {
            size_t input_offset = PICOKEYS_VAULT_CONTAINER_HEADER_SIZE + i * record_size;
            memcpy(updated + output_offset, data + input_offset, record_size);
            output_offset += record_size;
        }
    }
    int ret = file_put_data(file, CONST_BYTE_ARRAY(updated, output_offset));
    mbedtls_platform_zeroize(updated, data_len);
    free(updated);
    return ret;
}

int picokeys_vault_clear_file(file_t *file) {
    if (!file) {
        return PICOKEYS_OK;
    }
    meta_delete_no_commit(file->fid);
    return flash_clear_file(file);
}

int picokeys_vault_unenroll(file_t *file, file_t *label_file, uint8_t app_id) {
    picokeys_vault_enrollment_reset();
    int ret = vault_remove_record(file, app_id);
    if (ret == PICOKEYS_OK && !flash_commit_sync(5000)) {
        ret = PICOKEYS_ERR_MEMORY_FATAL;
    }
    if (ret == PICOKEYS_OK) {
        ret = picokeys_vault_clear_file(label_file);
    }
    if (ret == PICOKEYS_OK && !flash_commit_sync(5000)) {
        ret = PICOKEYS_ERR_MEMORY_FATAL;
    }
    picokeys_vault_enrollment_reset();
    return ret;
}

bool picokeys_vault_algorithm_valid(uint8_t algorithm) {
    return algorithm >= PICOKEYS_VAULT_ALGORITHM_CHACHAPOLY && algorithm <= PICOKEYS_VAULT_ALGORITHM_AESGCM_CHACHAPOLY;
}

size_t picokeys_vault_algorithm_layers(uint8_t algorithm) {
    return algorithm >= PICOKEYS_VAULT_ALGORITHM_CHACHAPOLY_AESGCM ? 2u : 1u;
}

uint8_t picokeys_vault_algorithm_layer(uint8_t algorithm, size_t index) {
    if (algorithm == PICOKEYS_VAULT_ALGORITHM_CHACHAPOLY_AESGCM) {
        return index == 0 ? PICOKEYS_VAULT_ALGORITHM_CHACHAPOLY : PICOKEYS_VAULT_ALGORITHM_AESGCM;
    }
    if (algorithm == PICOKEYS_VAULT_ALGORITHM_AESGCM_CHACHAPOLY) {
        return index == 0 ? PICOKEYS_VAULT_ALGORITHM_AESGCM : PICOKEYS_VAULT_ALGORITHM_CHACHAPOLY;
    }
    return algorithm;
}
