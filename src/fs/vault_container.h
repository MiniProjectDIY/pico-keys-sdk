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
#include "crypto_utils.h"
#include "file.h"

#define PICOKEYS_VAULT_CONTAINER_HEADER_SIZE 6u
#define PICOKEYS_VAULT_CONTAINER_RECORD_PREFIX_SIZE 1u
#define PICOKEYS_VAULT_KEY_SIZE 32u
#define PICOKEYS_VAULT_X448_BYTES 56u
#define PICOKEYS_VAULT_BLOB_NONCE_SIZE 12u
#define PICOKEYS_VAULT_BLOB_TAG_SIZE 16u
#define PICOKEYS_VAULT_ALGORITHM_CHACHAPOLY 1u
#define PICOKEYS_VAULT_ALGORITHM_AESGCM 2u
#define PICOKEYS_VAULT_ALGORITHM_CHACHAPOLY_AESGCM 3
#define PICOKEYS_VAULT_ALGORITHM_AESGCM_CHACHAPOLY 4
#define PICOKEYS_VAULT_ENROLL_CHALLENGE_BYTES 32u
#define PICOKEYS_VAULT_ENROLL_WINDOW_MS 60000u
#define PICOKEYS_VAULT_ENROLL_HOLD_MS 10000u
#define PICOKEYS_VAULT_ENROLL_CERT_MAX 1900u
#define PICOKEYS_VAULT_ENROLL_PLAIN_MAX (PICOKEYS_VAULT_KEY_SIZE + 1u + 64u)
#define PICOKEYS_VAULT_ENROLL_MIN_PACKET_LEN (2u + 12u + PICOKEYS_VAULT_KEY_SIZE + 16u)
#define PICOKEYS_VAULT_RECORD_FORMAT PIN_KDF_V2
#define PICOKEYS_VAULT_RECORD_SIZE (1u + PIN_KDF_SIZE(PICOKEYS_VAULT_KEY_SIZE))

bool picokeys_vault_container_valid(const uint8_t *data, size_t data_len, size_t record_size);
bool picokeys_vault_record_valid(const uint8_t *record, size_t record_len);
const uint8_t *picokeys_vault_find_record(const file_t *file, uint8_t app_id, size_t record_size);
bool picokeys_vault_record_available(const file_t *file, uint8_t app_id);
int picokeys_vault_store_record(file_t *file, uint8_t app_id, bool preserve_legacy_when_empty, const_byte_array_t record, uint8_t *scratch, size_t scratch_size);
int picokeys_vault_wrap(const uint8_t wrapping_key[PICOKEYS_VAULT_KEY_SIZE], const uint8_t kvault[PICOKEYS_VAULT_KEY_SIZE], uint8_t record[PICOKEYS_VAULT_RECORD_SIZE]);
int picokeys_vault_unwrap(const uint8_t wrapping_key[PICOKEYS_VAULT_KEY_SIZE], const uint8_t record[PICOKEYS_VAULT_RECORD_SIZE], uint8_t kvault[PICOKEYS_VAULT_KEY_SIZE]);
int picokeys_vault_load_kvault(const file_t *file, uint8_t app_id, const uint8_t wrapping_key[PICOKEYS_VAULT_KEY_SIZE], uint8_t kvault[PICOKEYS_VAULT_KEY_SIZE]);
int picokeys_vault_store_kvault(file_t *file, uint8_t app_id, bool preserve_legacy_when_empty, const uint8_t wrapping_key[PICOKEYS_VAULT_KEY_SIZE], const uint8_t kvault[PICOKEYS_VAULT_KEY_SIZE]);
int picokeys_vault_hash_kvault(const uint8_t kvault[PICOKEYS_VAULT_KEY_SIZE], uint8_t vault_id[PICOKEYS_VAULT_KEY_SIZE]);
int picokeys_vault_layer_key(const uint8_t key[PICOKEYS_VAULT_KEY_SIZE], const uint8_t vault_id[PICOKEYS_VAULT_KEY_SIZE], const uint8_t credential_hash[PICOKEYS_VAULT_KEY_SIZE], uint8_t algorithm, uint8_t layer, uint8_t out[PICOKEYS_VAULT_KEY_SIZE]);
int picokeys_vault_encrypt_layer(uint8_t algorithm, const uint8_t key[PICOKEYS_VAULT_KEY_SIZE], const uint8_t nonce[PICOKEYS_VAULT_BLOB_NONCE_SIZE], const uint8_t *aad, size_t aad_len, const uint8_t *input, size_t input_len, uint8_t *output, uint8_t tag[PICOKEYS_VAULT_BLOB_TAG_SIZE]);
int picokeys_vault_decrypt_layer(uint8_t algorithm, const uint8_t key[PICOKEYS_VAULT_KEY_SIZE], const uint8_t nonce[PICOKEYS_VAULT_BLOB_NONCE_SIZE], const uint8_t *aad, size_t aad_len, const uint8_t *input, size_t input_len, const uint8_t tag[PICOKEYS_VAULT_BLOB_TAG_SIZE], uint8_t *output);
int picokeys_vault_clear_wrappers(file_t *file, uint8_t preserve_app_id);
int picokeys_vault_x448_generate(uint8_t private_key[PICOKEYS_VAULT_X448_BYTES], uint8_t public_key[PICOKEYS_VAULT_X448_BYTES]);
int picokeys_vault_x448_shared(const uint8_t private_key[PICOKEYS_VAULT_X448_BYTES], const uint8_t peer_public[PICOKEYS_VAULT_X448_BYTES], uint8_t shared[PICOKEYS_VAULT_X448_BYTES]);
bool picokeys_vault_enrollment_active(void);
bool picokeys_vault_enrollment_button_ready(void);
int picokeys_vault_enrollment_start(uint8_t public_key[PICOKEYS_VAULT_X448_BYTES], uint8_t challenge[PICOKEYS_VAULT_ENROLL_CHALLENGE_BYTES]);
void picokeys_vault_enrollment_clear(void);
void picokeys_vault_enrollment_reset(void);
int picokeys_vault_enrollment_finish(const uint8_t *packet, size_t packet_len, file_t *file, uint8_t app_id, const uint8_t wrapping_key[PICOKEYS_VAULT_KEY_SIZE], uint8_t *metadata, size_t metadata_capacity, size_t *metadata_len);
bool picokeys_vault_algorithm_valid(uint8_t algorithm);
size_t picokeys_vault_algorithm_layers(uint8_t algorithm);
uint8_t picokeys_vault_algorithm_layer(uint8_t algorithm, size_t layer);
int picokeys_vault_clear_file(file_t *file);
int picokeys_vault_unenroll(file_t *file, file_t *label_file, uint8_t app_id);

#endif // _VAULT_CONTAINER_H_
