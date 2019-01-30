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

#include <string.h>
#include "ledger_keys.h"
#include "crypto_enclave.h"
#include "data_records_crypto.h"
#ifdef SGX_ENCLAVE
#include "enclave_log.h"
#else
#include "app_log.h"
#endif

// todo - review this code, knowing that for each enclave svn, there is an acl transaction with new ACL list

bool data_record_encrypt(e_record_type record_type, uint16_t acl_svn,
						 const public_ec_key_str_t *public_key, const char *txn_nonce_str, const ledger_hex_address_t *address,
						 const uint8_t *plain_data, uint32_t plain_data_size,
						 uint8_t **encrypted_data, uint32_t *encrypted_data_size)
{
	bool retval = false;

	kdf32_key_t aes_siv_key = {};

	if (public_key == NULL || txn_nonce_str == NULL || address == NULL ||
		plain_data == NULL || plain_data_size == 0 ||
		encrypted_data == NULL || encrypted_data_size == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}

	if (plain_data_size > MAX_CRYPTO_BUFFER_SIZE)
	{
		PRINT(ERROR, CRYPTO, "buffer size is too big\n");
		return false;
	}

	if (ledger_keys_manager.keys_ready() == false)
	{
		PRINT(ERROR, CRYPTO, "ledger keys are not initialized\n\n");
		return false;
	}
	if(record_type != DATA_TYPE && record_type != ACL_TYPE)
	{
		PRINT(ERROR, CRYPTO, "Unknown record type\n");
		return false;
	}

	if (acl_svn > ledger_keys_manager.get_svn())
	{
		PRINT(ERROR, CRYPTO, "ACL svn is bigger than the enclave's svn\n");
		return false;
	}

	size_t encrypted_record_size = sizeof(encrypted_record_t) + plain_data_size + AES_SIV_IV_SIZE;
	encrypted_record_t *p_encrypted_record = (encrypted_record_t *)malloc(encrypted_record_size);
	if (p_encrypted_record == NULL)
	{
		PRINT(ERROR, CRYPTO, "malloc failed\n");
		return false;
	}
	memset_s(p_encrypted_record, encrypted_record_size, 0, encrypted_record_size);

	do
	{

		if (sha256_msg((const uint8_t *)address->data, sizeof(ledger_hex_address_t), &p_encrypted_record->address_hash) == false)
		{
			PRINT(ERROR, CRYPTO, "sha256_msg failed\n");
			break;
		}

		// the transaction nonce length is user-defined, putting a max of ONE_KB
		size_t txn_nonce_len = strnlen(txn_nonce_str, ONE_KB);
		if (txn_nonce_len >= ONE_KB - 1)
		{
			PRINT(ERROR, CRYPTO, "transaction nonce length is too long\n");
			break;
		}

		if (sha256_msg((const uint8_t *)txn_nonce_str, (uint32_t)txn_nonce_len, &p_encrypted_record->transaction_nonce_hash) == false)
		{
			PRINT(ERROR, CRYPTO, "sha256_msg failed\n");
			break;
		}

		if (sha256_msg((const uint8_t *)public_key->data, (uint32_t)sizeof(public_ec_key_str_t), &p_encrypted_record->public_key_hash) == false)
		{
			PRINT(ERROR, CRYPTO, "sha256_msg failed\n");
			break;
		}

		if (generate_aes_siv_key(ledger_keys_manager.get_kds_by_svn(acl_svn),
								 p_encrypted_record->public_key_hash, p_encrypted_record->transaction_nonce_hash, p_encrypted_record->address_hash,
								 &aes_siv_key) == false)
		{
			PRINT(ERROR, CRYPTO, "generate_aes_siv_key failed\n");
			break;
		}
		
		p_encrypted_record->aad.record_type = record_type;
		p_encrypted_record->aad.acl_svn = acl_svn;
		p_encrypted_record->aad.plain_data_size = plain_data_size;

		if (aes_siv_encrypt(plain_data, plain_data_size,
							(const uint8_t *)&p_encrypted_record->aad, sizeof(aes_siv_aad_t),
							aes_siv_key, sizeof(kdf32_key_t),
							p_encrypted_record->encrypted_data, plain_data_size + AES_SIV_IV_SIZE) == false)
		{
			PRINT(ERROR, CRYPTO, "aes_siv_encrypt failed\n");
			break;
		}

		*encrypted_data = (uint8_t *)p_encrypted_record;
		*encrypted_data_size = (uint32_t)encrypted_record_size;
		retval = true;

	} while (0);

	// cleanup
	memset_s(aes_siv_key, sizeof(kdf32_key_t), 0, sizeof(kdf32_key_t)); // todo - perhaps replace all the key hiding with random?

	if (retval == false && p_encrypted_record != NULL)
		free(p_encrypted_record);

	return retval;
}

bool data_record_decrypt(const uint8_t *encrypted_data, uint32_t encrypted_data_size,
						 uint16_t cur_acl_svn, const ledger_hex_address_t *address,
						 uint8_t **plain_data, uint32_t *plain_data_size)
{
	bool retval = false;

	kdf32_key_t aes_siv_key = {};
	sha256_data_t address_hash = {};

	uint8_t *decrypted_data = NULL;
	encrypted_record_t *p_encrypted_record = (encrypted_record_t *)encrypted_data;

	if (encrypted_data == NULL || encrypted_data_size < sizeof(encrypted_record_t) + AES_SIV_IV_SIZE ||
		address == NULL || plain_data == NULL || plain_data_size == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}

	if (encrypted_data_size > MAX_CRYPTO_BUFFER_SIZE)
	{
		PRINT(ERROR, CRYPTO, "buffer size is too big\n");
		return false;
	}

	if (ledger_keys_manager.keys_ready() == false)
	{
		PRINT(ERROR, CRYPTO, "ledger keys are not initialized\n\n");
		return false;
	}

	if (p_encrypted_record->aad.plain_data_size != encrypted_data_size - sizeof(encrypted_record_t) - AES_SIV_IV_SIZE)
	{
		PRINT(ERROR, CRYPTO, "encrypted record size is wrong\n");
		return false;
	}

	if (p_encrypted_record->aad.acl_svn > cur_acl_svn)
	{
		PRINT(ERROR, CRYPTO, "svn in the record is newer than the enclave's ACL svn\n");
		return false;
	}

	if (p_encrypted_record->aad.acl_svn > ledger_keys_manager.get_svn())
	{
		PRINT(ERROR, CRYPTO, "svn in the record is newer than the enclave's svn\n");
		return false;
	}
	if(p_encrypted_record->aad.record_type != DATA_TYPE && p_encrypted_record->aad.record_type != ACL_TYPE)
	{
		PRINT(ERROR, CRYPTO, "Unknown record type\n");
		return false;
	}

	do
	{
		// ignore the addess hash in the record, simply overwrite it with the right value,
		// if an attacker will give us a record from another address, the generated key will be wrong
		if (sha256_msg((const uint8_t *)address->data, (uint32_t)sizeof(ledger_hex_address_t), &address_hash) == false)
		{
			PRINT(ERROR, CRYPTO, "sha256_msg failed\n");
			break;
		}

		if (generate_aes_siv_key(ledger_keys_manager.get_kds_by_svn(p_encrypted_record->aad.acl_svn),
								 p_encrypted_record->public_key_hash, p_encrypted_record->transaction_nonce_hash, address_hash,
								 &aes_siv_key) == false)
		{
			PRINT(ERROR, CRYPTO, "generate_aes_siv_key failed\n");
			break;
		}
		
		decrypted_data = (uint8_t *)malloc(p_encrypted_record->aad.plain_data_size);
		if (decrypted_data == NULL)
		{
			PRINT(ERROR, CRYPTO, "malloc failed\n");
			break;
		}
		memset_s(decrypted_data, p_encrypted_record->aad.plain_data_size, 0, p_encrypted_record->aad.plain_data_size);

		if (aes_siv_decrypt(p_encrypted_record->encrypted_data, p_encrypted_record->aad.plain_data_size + AES_SIV_IV_SIZE,
							(uint8_t *)&p_encrypted_record->aad, sizeof(aes_siv_aad_t),
							aes_siv_key, sizeof(kdf32_key_t),
							decrypted_data, p_encrypted_record->aad.plain_data_size) == false)
		{
			PRINT(ERROR, CRYPTO, "aes_siv_decrypt failed\n");
			break;
		}

		*plain_data = decrypted_data;
		*plain_data_size = p_encrypted_record->aad.plain_data_size;
		retval = true;

	} while (0);

	// cleanup
	memset_s(aes_siv_key, sizeof(kdf32_key_t), 0, sizeof(kdf32_key_t));

	if (retval == false && decrypted_data != NULL)
		free(decrypted_data);

	return retval;
}
