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
 
#include "crypto.h"
#ifdef SGX_ENCLAVE
#include "enclave_log.h"
#else
#include "app_log.h"
#endif

#include <openssl/cmac.h>

bool sha256_msg(const uint8_t* data, size_t data_size, sha256_data_t* out_hash)
{
	if (data == NULL || data_size == 0 || out_hash == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}
	
	if (data_size > MAX_CRYPTO_BUFFER_SIZE)
	{
		PRINT(ERROR, CRYPTO, "buffer size is too big\n");
		return false;
	}
	
	if (SHA256(data, data_size, *out_hash) == NULL) 
	{
		PRINT(ERROR, CRYPTO, "SHA256 failed\n");
		return false;
	}
	
	return true;
}


bool sha512_msg(const uint8_t* data, size_t data_size, sha512_data_t* out_hash)
{
	if (data == NULL || data_size == 0 || out_hash == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}
	
	if (data_size > MAX_CRYPTO_BUFFER_SIZE)
	{
		PRINT(ERROR, CRYPTO, "buffer size is too big\n");
		return false;
	}
	
	if (SHA512(data, data_size, *out_hash) == NULL) 
	{
		PRINT(ERROR, CRYPTO, "SHA512 failed\n");
		return false;
	}
	
	return true;
}


bool cmac_msg(const uint8_t* key, size_t key_size, const void* msg, size_t msg_size, uint8_t* out_mac, size_t out_mac_size)
{
	CMAC_CTX *ctx = NULL;
	size_t mac_size = 0;
	bool ret = false;
	
	if (key == NULL || key_size != CMAC_KEY_SIZE || msg == NULL || msg_size == 0 || out_mac == NULL || out_mac_size != CMAC_KEY_SIZE)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}
	
	if (msg_size > MAX_CRYPTO_BUFFER_SIZE)
	{
		PRINT(ERROR, CRYPTO, "buffer size is too big\n");
		return false;
	}
	
	do {
	
		ctx = CMAC_CTX_new();
		if (ctx == NULL)
		{
			PRINT(ERROR, CRYPTO, "CMAC_CTX_new failed\n");
			break;
		}
			
		if (CMAC_Init(ctx, key, key_size, EVP_aes_128_cbc(), NULL) == 0) // todo - check aes mode - cbc or ctr?
		{
			PRINT(ERROR, CRYPTO, "CMAC_Init failed\n");
			break;
		}
	 
		if (CMAC_Update(ctx, msg, msg_size) == 0)
		{
			PRINT(ERROR, CRYPTO, "CMAC_Update failed\n");
			break;
		}
		
		if (CMAC_Final(ctx, out_mac, &mac_size) == 0)
		{
			PRINT(ERROR, CRYPTO, "CMAC_Final failed\n");
			break;
		}
			
		if (mac_size != CMAC_KEY_SIZE)
		{
			PRINT(ERROR, CRYPTO, "incorrect mac size\n");
			break;
		}
		
		ret = true;
	
	} while (0);
	
	if (ctx != NULL)	
		CMAC_CTX_free(ctx);
	
	return ret;
}

