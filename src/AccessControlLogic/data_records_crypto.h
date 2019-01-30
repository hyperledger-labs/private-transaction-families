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


#ifndef _DATA_RECORDS_CRYPTO_H_
#define _DATA_RECORDS_CRYPTO_H_

#include "crypto_enclave.h"

typedef enum {
	DATA_TYPE,
	ACL_TYPE,
} e_record_type;

#pragma pack(1)

typedef struct {
	e_record_type record_type;
	uint16_t acl_svn;
	uint32_t plain_data_size;
} aes_siv_aad_t;

typedef struct {
	aes_siv_aad_t aad;
	sha256_data_t address_hash; // not really needed, enclave knows the address, and do not use this value when decrypting. leave it for debug purposes etc. todo - re-think this
	sha256_data_t transaction_nonce_hash; // transaction that caused the record change
	sha256_data_t public_key_hash; // client who signed the transaction that caused the record change
	uint8_t encrypted_data[]; // size should be 'aad.plain_data_size + 16'
} encrypted_record_t;

#pragma pack()

bool data_record_encrypt(e_record_type record_type, uint16_t acl_svn, 
						 const public_ec_key_str_t* public_key, const char* txn_nonce_str, const ledger_hex_address_t* address, 
						 const uint8_t* plain_data, uint32_t plain_data_size, 
						 uint8_t** encrypted_data, uint32_t* encrypted_data_size); // output, must be free'ed by the caller

bool data_record_decrypt(const uint8_t* encrypted_data, uint32_t encrypted_data_size, 
						 uint16_t cur_acl_svn, const ledger_hex_address_t* address,
						 uint8_t** plain_data, uint32_t* plain_data_size); // output, must be free'ed by the caller

#endif // _DATA_RECORDS_CRYPTO_H_
