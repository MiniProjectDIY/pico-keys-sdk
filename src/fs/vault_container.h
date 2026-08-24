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

#ifndef _VAULT_CONTAINER_H_
#define _VAULT_CONTAINER_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "byte_array.h"
#include "file.h"
#include "../vault.h"

#define PICOKEYS_VAULT_CONTAINER_HEADER_SIZE 6u
#define PICOKEYS_VAULT_CONTAINER_RECORD_PREFIX_SIZE 1u
#define PICOKEYS_VAULT_RECORD_FORMAT PIN_KDF_V2
#define PICOKEYS_VAULT_RECORD_SIZE (1u + PIN_KDF_SIZE(PICOKEYS_VAULT_KEY_SIZE))

extern bool picokeys_vault_container_valid(const uint8_t *data, size_t data_len, size_t record_size);
extern bool picokeys_vault_record_valid(const uint8_t *record, size_t record_len);
extern const uint8_t *picokeys_vault_find_record(const file_t *file, uint8_t app_id, size_t record_size);
extern bool picokeys_vault_record_available(const file_t *file, uint8_t app_id);
extern int picokeys_vault_store_record(file_t *file, uint8_t app_id, const_byte_array_t record, uint8_t *scratch, size_t scratch_size);
extern int picokeys_vault_wrap(const uint8_t wrapping_key[PICOKEYS_VAULT_KEY_SIZE], const uint8_t kvault[PICOKEYS_VAULT_KEY_SIZE], uint8_t record[PICOKEYS_VAULT_RECORD_SIZE]);
extern int picokeys_vault_unwrap(const uint8_t wrapping_key[PICOKEYS_VAULT_KEY_SIZE], const uint8_t record[PICOKEYS_VAULT_RECORD_SIZE], uint8_t kvault[PICOKEYS_VAULT_KEY_SIZE]);
extern int picokeys_vault_load_kvault(const file_t *file, uint8_t app_id, const uint8_t wrapping_key[PICOKEYS_VAULT_KEY_SIZE], uint8_t kvault[PICOKEYS_VAULT_KEY_SIZE]);
extern int picokeys_vault_store_kvault(file_t *file, uint8_t app_id, const uint8_t wrapping_key[PICOKEYS_VAULT_KEY_SIZE], const uint8_t kvault[PICOKEYS_VAULT_KEY_SIZE]);
extern int picokeys_vault_clear_wrapper(file_t *file, uint8_t app_id);

#endif // _VAULT_CONTAINER_H_
