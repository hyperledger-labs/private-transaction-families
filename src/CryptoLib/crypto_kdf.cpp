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
#include "crypto.h"
#include <openssl/hmac.h>

#include "crypto_kdf_strings.h"

#ifdef SGX_ENCLAVE
#include "enclave_log.h"
#else
#include "app_log.h"
#endif

bool derive_16bytes_key_from_double_cmac_aes_128(const char* label1, kdf_nonce_t nonce1, const char* label2, kdf_nonce_t nonce2, kdf16_key_t* out_key)
{
	kdf16_key_t empty_key = {0};
	kdf16_key_t derived_key = {0};
	kdf_input_t kdf_input = {};
	bool ret = false;
	
	// todo - check labels length?
	if (label1 == NULL || label2 == NULL || out_key == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}
		
	do {
	
		kdf_input.index = 1;
		if (safe_strncpy(kdf_input.label, KDF_LABEL_LEN, label1, KDF_LABEL_LEN) == false)
		{
			PRINT(ERROR, CRYPTO, "safe_strncpy failed\n");
			break;
		}
		if (safe_memcpy(kdf_input.nonce, sizeof(kdf_nonce_t), nonce1, sizeof(kdf_nonce_t)) == false)
		{
			PRINT(ERROR, CRYPTO, "safe_memcpy failed\n");
			break;
		}
		kdf_input.output_len = KDF16_KEY_SIZE * 8;
		
		if (cmac_msg(empty_key, KDF16_KEY_SIZE, (unsigned char*)&kdf_input, sizeof(kdf_input_t), derived_key, KDF16_KEY_SIZE) == false)
		{
			PRINT(ERROR, CRYPTO, "cmac_msg failed\n");
			break;
		}
		
		memset_s(&kdf_input, sizeof(kdf_input_t), 0, sizeof(kdf_input_t));
		kdf_input.index = 1;
		if (safe_strncpy(kdf_input.label, KDF_LABEL_LEN, label2, KDF_LABEL_LEN) == false)
		{
			PRINT(ERROR, CRYPTO, "safe_strncpy failed\n");
			break;
		}
		if (safe_memcpy(kdf_input.nonce, sizeof(kdf_nonce_t), nonce2, sizeof(kdf_nonce_t)) == false)
		{
			PRINT(ERROR, CRYPTO, "safe_memcpy failed\n");
			break;
		}
		kdf_input.output_len = KDF16_KEY_SIZE * 8;
		
		if (cmac_msg(derived_key, KDF16_KEY_SIZE, (unsigned char*)&kdf_input, sizeof(kdf_input_t), *out_key, KDF16_KEY_SIZE) == false)
		{
			PRINT(ERROR, CRYPTO, "cmac_msg failed\n");
			break;
		}
		
		ret = true;
	
	} while (0);
	
	// cleanup
	memset_s(derived_key, sizeof(kdf16_key_t), 0, sizeof(kdf16_key_t));
	memset_s(&kdf_input, sizeof(kdf_input_t), 0, sizeof(kdf_input_t));
	
	return ret;
}



bool derive_32bytes_key_from_double_hmac_sha_256(const char* label1, kdf_nonce_t nonce1, const char* label2, kdf_nonce_t nonce2, kdf_record_data_t* p_record_data, kdf32_key_t* out_key)
{
	kdf32_key_t empty_key = {0};
	kdf32_key_t derived_key = {0};
	kdf_input_t kdf_input = {};
	uint32_t output_len = sizeof(kdf32_key_t);
	bool ret = false;
	
	// todo - check label length?
	if (label1 == NULL || label2 == NULL || out_key == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}
	
	do {
	
		kdf_input.index = 1;
		if (safe_strncpy(kdf_input.label, KDF_LABEL_LEN, label1, KDF_LABEL_LEN) == false)
		{
			PRINT(ERROR, CRYPTO, "safe_strncpy failed\n");
			break;
		}
		if (safe_memcpy(kdf_input.nonce, sizeof(kdf_nonce_t), nonce1, sizeof(kdf_nonce_t)) == false)
		{
			PRINT(ERROR, CRYPTO, "safe_memcpy failed\n");
			break;
		}
		kdf_input.output_len = KDF32_KEY_SIZE * 8;
		
		if (HMAC(EVP_sha256(), empty_key, KDF32_KEY_SIZE, (unsigned char*)&kdf_input, sizeof(kdf_input_t), derived_key, &output_len) == NULL)
		{
			PRINT(ERROR, CRYPTO, "HMAC failed\n");
			break;
		}
		if (output_len != sizeof(kdf32_key_t))
		{
			PRINT(ERROR, CRYPTO, "HMAC output length is incorrect\n");
			break;
		}
		
		memset_s(&kdf_input, sizeof(kdf_input_t), 0, sizeof(kdf_input_t));
		kdf_input.index = 1;
		if (safe_strncpy(kdf_input.label, KDF_LABEL_LEN, label2, KDF_LABEL_LEN) == false)
		{
			PRINT(ERROR, CRYPTO, "safe_strncpy failed\n");
			break;
		}
		if (safe_memcpy(kdf_input.nonce, sizeof(kdf_nonce_t), nonce2, sizeof(kdf_nonce_t)) == false)
		{
			PRINT(ERROR, CRYPTO, "safe_memcpy failed\n");
			break;
		}
		if (p_record_data != NULL)
		{
			if (safe_memcpy(&kdf_input.record_data, sizeof(kdf_record_data_t), p_record_data, sizeof(kdf_record_data_t)) == false)
			{
				PRINT(ERROR, CRYPTO, "safe_memcpy failed\n");
				break;
			}
		}
		kdf_input.output_len = KDF32_KEY_SIZE * 8; // length in bits
		
		if (HMAC(EVP_sha256(), derived_key, KDF32_KEY_SIZE, (unsigned char*)&kdf_input, sizeof(kdf_input_t), *out_key, &output_len) == NULL)
		{
			PRINT(ERROR, CRYPTO, "HMAC failed\n");
			break;
		}
		if (output_len != KDF32_KEY_SIZE)
		{
			PRINT(ERROR, CRYPTO, "HMAC output length is incorrect\n");
			break;
		}
		
		ret = true;
	
	} while (0);
	
	// cleanup
	memset_s(derived_key, sizeof(kdf32_key_t), 0, sizeof(kdf32_key_t));
	memset_s(&kdf_input, sizeof(kdf_input_t), 0, sizeof(kdf_input_t));
	
	return ret;
}


bool generate_previous_svn_kds(const kdf32_key_t* p_cur_kds, kdf32_key_t* p_prev_kds, uint16_t svn)
{
	kdf_nonce_t kdf_nonce1 = {0};
	kdf_nonce_t kdf_nonce2 = {0};
	
	if (p_cur_kds == NULL || p_prev_kds == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}
	
	if (safe_memcpy(kdf_nonce1, sizeof(kdf_nonce_t), *p_cur_kds, sizeof(kdf32_key_t)) == false ||
	    safe_memcpy(kdf_nonce2, sizeof(kdf_nonce_t), &svn, sizeof(uint16_t)) == false)
	{
		PRINT(ERROR, CRYPTO, "safe_memcpy failed\n");
		return false;
	}
	
	if (derive_32bytes_key_from_double_hmac_sha_256(KDS_1ST_DERIVATION_LABEL, kdf_nonce1, KDS_2ND_DERIVATION_LABEL, kdf_nonce2, NULL, p_prev_kds) == false)
	{
		PRINT(ERROR, GENESIS,  "derive_32bytes_key_from_double_hmac_sha_256 failed\n");
		return false;
	}
		
	return true;
}
