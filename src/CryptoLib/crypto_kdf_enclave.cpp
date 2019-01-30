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

#include <openssl/rand.h>

#include <sgx_thread.h>

#include "crypto.h"
#include "crypto_enclave.h"
#include "crypto_kdf_strings.h"
#include "ledger_keys.h"
#include "PrivateLedger.h"

#ifdef SGX_ENCLAVE
#include "enclave_log.h"
#else
#include "app_log.h"
#endif

// defined in crypto_rand_engine.cpp
extern RAND_METHOD kdf_rand_meth;
extern sgx_thread_t rand_owner_thread;
extern const char* g_kdf_key_string;

sgx_thread_mutex_t kds_mutex = SGX_THREAD_MUTEX_INITIALIZER;


bool generate_ledger_sign_keys_from_kds(kdf32_key_t ledger_kds, public_ec_key_str_t* sign_pub_ec_key_str, private_ec_key_str_t* sign_priv_ec_key_str)
{
	EC_KEY* sign_key = NULL;
	bool ret = false;
	
	if (sign_pub_ec_key_str == NULL || sign_priv_ec_key_str == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}
	
	sgx_thread_mutex_lock(&kds_mutex);
	
	rand_owner_thread = sgx_thread_self();
	
	// save the original random engine
	const RAND_METHOD* default_rm = RAND_get_rand_method();
	
	// replace the random engine with the PRNG based on KDF
	RAND_set_rand_method(&kdf_rand_meth);
	
	do {			
		// generate the signing key
		RAND_seed(ledger_kds, sizeof(kdf32_key_t));
		g_kdf_key_string = ECKEY_SIGN_2ND_DERIVATION_LABEL;
		
		if (create_new_ec_key_pair(&sign_key) == false)
		{
			PRINT(ERROR, CRYPTO,  "create_new_ec_key_pair failed\n");
			break;
		}

		if (get_ec_public_key_as_str(sign_key, sign_pub_ec_key_str) == false)
		{
			PRINT(ERROR, CRYPTO,  "get_ec_public_key_as_str failed\n");
			break;
		}
		
		if (get_ec_private_key_as_str(sign_key, sign_priv_ec_key_str) == false)
		{
			PRINT(ERROR, CRYPTO,  "get_ec_private_key_as_str failed\n");
			break;
		}
		
		ret = true;
		
	} while (0);
	
	// cleanup
	if (sign_key != NULL)
		EC_KEY_free(sign_key);
	
	// clear the KDS and derived EC private key from the PRNG
	RAND_cleanup();
	
	// restore the original random engine
	RAND_set_rand_method(default_rm);
	
	rand_owner_thread = 0;
	
	sgx_thread_mutex_unlock(&kds_mutex);
		
	return ret;
}


bool generate_ledger_keys_from_kds(kdf32_key_t ledger_kds, ledger_keys_t* p_ledger_keys)
{
	EC_KEY* data_key = NULL;
	bool ret = false;
	
	if (p_ledger_keys == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}
	
	sgx_thread_mutex_lock(&kds_mutex);
	
	rand_owner_thread = sgx_thread_self();
	
	// save the original random engine
	const RAND_METHOD* default_rm = RAND_get_rand_method();
	
	// replace the random engine with the PRNG based on KDF
	RAND_set_rand_method(&kdf_rand_meth);
	
	do {			
		// generate the data key
		RAND_seed(ledger_kds, sizeof(kdf32_key_t));
		g_kdf_key_string = ECKEY_DATA_2ND_DERIVATION_LABEL;
		
		if (create_new_ec_key_pair(&data_key) == false)
		{
			PRINT(ERROR, CRYPTO,  "create_new_ec_key_pair failed\n");
			break;
		}

		if (get_ec_public_key_as_str(data_key, &p_ledger_keys->data_pub_ec_key_str) == false)
		{
			PRINT(ERROR, CRYPTO,  "get_ec_public_key_as_str failed\n");
			break;
		}
		
		if (get_ec_private_key_as_str(data_key, &p_ledger_keys->data_priv_ec_key_str) == false)
		{
			PRINT(ERROR, CRYPTO,  "get_ec_private_key_as_str failed\n");
			break;
		}
				
		ret = true;
		
	} while (0);
	
	// cleanup
	if (data_key != NULL)
		EC_KEY_free(data_key);
	
	// clear the KDS and derived EC private key from the PRNG
	RAND_cleanup();
	
	// restore the original random engine
	RAND_set_rand_method(default_rm);
	
	rand_owner_thread = 0;
	
	sgx_thread_mutex_unlock(&kds_mutex);
		
	return ret;
}


bool generate_aes_siv_key(const kdf32_key_t* ledger_kds, sha256_data_t public_key_hash, sha256_data_t transaction_nonce_hash, sha256_data_t address_hash, kdf32_key_t* aes_siv_key)
{
	kdf_nonce_t kdf_nonce1 = {0};
	kdf_nonce_t kdf_nonce2 = {0};
	kdf_record_data_t record_data = {};
	
	if (aes_siv_key == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}
	
	if (safe_memcpy(kdf_nonce1, sizeof(kdf_nonce_t), ledger_kds, sizeof(kdf32_key_t)) == false || // first nonce - the kds, same size as nonce_t
		safe_memcpy(kdf_nonce2, sizeof(kdf_nonce_t), public_key_hash, sizeof(sha256_data_t)) == false) // second nonce - the public key
	{
		PRINT(ERROR, CRYPTO, "safe_memcpy failed\n");
		return false;
	}
		
	// all the extra data
	if (safe_memcpy(record_data.transaction_nonce_hash, sizeof(sha256_data_t), transaction_nonce_hash, sizeof(sha256_data_t)) == false ||
		safe_memcpy(record_data.address_hash, sizeof(sha256_data_t), address_hash, sizeof(sha256_data_t)) == false)
	{
		PRINT(ERROR, CRYPTO, "safe_memcpy failed\n");
		return false;
	}
		
	if (derive_32bytes_key_from_double_hmac_sha_256(HMAC_1ST_DERIVATION_LABEL, kdf_nonce1, HMAC_2ND_DERIVATION_LABEL, kdf_nonce2, &record_data, aes_siv_key) == false)
	{
		PRINT(ERROR, CRYPTO,  "derive_32bytes_key_from_double_hmac_sha_256 failed\n");
		return false;
	}

	return true;
}



