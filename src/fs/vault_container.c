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
#include "flash.h"

static const uint8_t vault_container_magic[4] = { 'K', 'V', 'W', '1' };

static bool vault_legacy_record_valid(const uint8_t *data, size_t data_len, size_t record_size) {
    return data_len == record_size && (record_size != PICOKEYS_VAULT_RECORD_SIZE || picokeys_vault_record_valid(data, data_len));
}

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
    if (app_id == 0 && vault_legacy_record_valid(data, data_len, record_size)) {
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
        if (vault_legacy_record_valid(data, data_len, record.len)) {
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

int picokeys_vault_clear_wrapper(file_t *file, uint8_t app_id) {
    if (!file) {
        return PICOKEYS_OK;
    }
    if (!file_has_data(file)) {
        meta_delete_no_commit(file->fid);
        return PICOKEYS_OK;
    }

    const uint8_t *data = file_get_data(file);
    size_t data_len = file_get_size(file);
    if (picokeys_vault_record_valid(data, data_len)) {
        if (app_id != 0) {
            return PICOKEYS_OK;
        }
        meta_delete_no_commit(file->fid);
        return flash_clear_file(file);
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
        meta_delete_no_commit(file->fid);
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
