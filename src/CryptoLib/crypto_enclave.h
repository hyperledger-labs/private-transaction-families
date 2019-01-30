/*
* Copyright 2018 Intel Corporation
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
 
#ifndef _CRYPTO_ENCLAVE_H_
#define _CRYPTO_ENCLAVE_H_

#include "crypto_transaction.h"
#include "ledger_keys.h"

#define AES_SIV_KEY_SIZE 32
#define AES_SIV_IV_SIZE  16

/* crypto_kdf_enclave.cpp */
bool generate_aes_siv_key(const kdf32_key_t* ledger_kds, sha256_data_t public_key_hash, sha256_data_t transaction_nonce_hash, sha256_data_t address_hash, kdf32_key_t* aes_siv_key);

bool generate_ledger_sign_keys_from_kds(kdf32_key_t ledger_kds, public_ec_key_str_t* sign_pub_ec_key_str, private_ec_key_str_t* sign_priv_ec_key_str);
bool generate_ledger_keys_from_kds(kdf32_key_t ledger_kds, ledger_keys_t* p_ledger_keys);

/* crypto_aes_siv.cpp */
bool aes_siv_encrypt(const uint8_t* in_buf,  size_t in_buf_size, 
					const uint8_t* in_aad,  size_t in_aad_size,
					const uint8_t* aes_key, size_t aes_key_size, 
					uint8_t* out_buf, size_t out_buf_size);
					
bool aes_siv_decrypt(const uint8_t* in_buf,  size_t in_buf_size, 
					const uint8_t* in_aad,  size_t in_aad_size,
					const uint8_t* aes_key, size_t aes_key_size, 
					uint8_t* out_buf, size_t out_buf_size);

#endif // _CRYPTO_ENCLAVE_H_
