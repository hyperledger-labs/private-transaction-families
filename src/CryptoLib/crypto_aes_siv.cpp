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
#include "crypto_enclave.h"
#include "aes_siv.h"

#ifdef SGX_ENCLAVE
#include "enclave_log.h"
#else
#include "app_log.h"
#endif

bool aes_siv_encrypt(const uint8_t* in_buf,  size_t in_buf_size, 
					const uint8_t* in_aad,  size_t in_aad_size,
					const uint8_t* aes_key, size_t aes_key_size, 
					uint8_t* out_buf, size_t out_buf_size)
{
	AES_SIV_CTX *ctx = NULL;
	int ret = 0;
	size_t out_size = out_buf_size;
	bool retval = false;
	
	if (in_buf == NULL || in_buf_size == 0 ||
		(in_aad == NULL && in_aad_size != 0) ||
		aes_key == NULL || aes_key_size != AES_SIV_KEY_SIZE || // 384 and 512 are also supported, but not in our usage
		out_buf == NULL || out_buf_size != in_buf_size + AES_SIV_IV_SIZE)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}
	
	if (in_buf_size > MAX_CRYPTO_BUFFER_SIZE || in_aad_size > MAX_CRYPTO_BUFFER_SIZE)
	{
		PRINT(ERROR, CRYPTO, "buffer size is too big\n");
		return false;
	}
	
	do {

		ctx = AES_SIV_CTX_new();
		if (ctx == NULL)
		{
			PRINT(ERROR, CRYPTO, "AES_SIV_CTX_new failed\n");
			break;
		}

		ret = AES_SIV_Encrypt(ctx, out_buf, &out_size, 
							aes_key, aes_key_size, 
							NULL, 0, // nonce
							in_buf, in_buf_size,
							in_aad, in_aad_size);
		if (ret != 1)
		{
			PRINT(ERROR, CRYPTO, "AES_SIV_Encrypt failed, ret %d\n", ret);
			break;
		}
		
		if (out_size != out_buf_size)
		{
			PRINT(ERROR, CRYPTO, "AES_SIV_Encrypt returned wrong output size, %ld instead of %ld\n", out_size, out_buf_size);
			memset_s(out_buf, out_buf_size, 0, out_buf_size);
			break;
		}
		
		retval = true;
		
	} while(0);
		
	if (ctx != NULL)
		AES_SIV_CTX_free(ctx);
	
	return retval;
}


bool aes_siv_decrypt(const uint8_t* in_buf,  size_t in_buf_size, 
					const uint8_t* in_aad,  size_t in_aad_size,
					const uint8_t* aes_key, size_t aes_key_size, 
					uint8_t* out_buf, size_t out_buf_size)
{
	AES_SIV_CTX *ctx = NULL;
	int ret = 0;
	size_t out_size = out_buf_size;
	bool retval = false;
	
	if (in_buf == NULL || in_buf_size <= AES_SIV_IV_SIZE ||
		(in_aad == NULL && in_aad_size != 0) ||
		aes_key == NULL || aes_key_size != AES_SIV_KEY_SIZE || // 384 and 512 are also supported, but not in our usage
		out_buf == NULL || out_buf_size != in_buf_size - AES_SIV_IV_SIZE)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}
	
	if (in_buf_size > MAX_CRYPTO_BUFFER_SIZE || in_aad_size > MAX_CRYPTO_BUFFER_SIZE)
	{
		PRINT(ERROR, CRYPTO, "buffer size is too big\n");
		return false;
	}
	
	do {

		ctx = AES_SIV_CTX_new();
		if (ctx == NULL)
		{
			PRINT(ERROR, CRYPTO, "AES_SIV_CTX_new failed\n");
			break;
		}

		ret = AES_SIV_Decrypt(ctx, out_buf, &out_size, 
							aes_key, aes_key_size, 
							NULL, 0, // nonce
							in_buf, in_buf_size,
							in_aad, in_aad_size);
		if (ret != 1)
		{
			PRINT(ERROR, CRYPTO, "AES_SIV_Decrypt failed, ret %d\n", ret);
			break;
		}
		
		if (out_size != out_buf_size)
		{
			PRINT(ERROR, CRYPTO, "AES_SIV_Decrypt returned wrong output size, %ld instead of %ld\n", out_size, out_buf_size);
			memset_s(out_buf, out_buf_size, 0, out_buf_size);
			break;
		}
		
		retval = true;
		
	} while(0);
		
	if (ctx != NULL)
		AES_SIV_CTX_free(ctx);
	
	return retval;
}

