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

bool aes_encrypt(uint8_t* in_buf,  size_t in_buf_size, 
				 uint8_t* aes_key, size_t aes_key_size, 
				 uint8_t* out_iv,  size_t out_iv_size, // randomize inside this function
				 uint8_t* out_buf, size_t out_buf_size,
				 uint8_t* out_mac, size_t out_mac_size)
{
	if (in_buf == NULL  || in_buf_size == 0 ||
		aes_key == NULL || aes_key_size != AES_KEY_SIZE ||
		out_iv == NULL  || out_iv_size != AES_IV_SIZE ||
		out_buf == NULL || out_buf_size < in_buf_size ||
		out_mac == NULL || out_mac_size != AES_MAC_SIZE)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}
	
	if (in_buf_size > MAX_CRYPTO_BUFFER_SIZE || out_buf_size > MAX_CRYPTO_BUFFER_SIZE)
	{
		PRINT(ERROR, CRYPTO, "buffer size is too big\n");
		return false;
	}
		
	int len = (int)out_buf_size;
	bool ret = false;
	EVP_CIPHER_CTX* ctx = NULL;

	do {
		
		if (get_random_bytes(out_iv, AES_IV_SIZE) == false)
		{
			PRINT(ERROR, CRYPTO, "get_random_bytes failed\n");
			break;
		}
		
		ctx = EVP_CIPHER_CTX_new();
		if (ctx == NULL)
		{
			PRINT(ERROR, CRYPTO, "EVP_CIPHER_CTX_new failed\n");
			break;
		}
		
		if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, aes_key, out_iv) != 1)
		{
			PRINT(ERROR, CRYPTO, "EVP_EncryptInit_ex failed\n");
			break;
		}
		
		if (EVP_EncryptUpdate(ctx, out_buf, &len, in_buf, (int)in_buf_size) != 1)
		{
			PRINT(ERROR, CRYPTO, "EVP_EncryptUpdate failed\n");
			break;
		}

		if (EVP_EncryptFinal_ex(ctx, out_buf + len, &len) != 1)
		{
			PRINT(ERROR, CRYPTO, "EVP_EncryptFinal_ex failed\n");
			break;
		}

		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_MAC_SIZE, out_mac) != 1)
		{
			PRINT(ERROR, CRYPTO, "EVP_CIPHER_CTX_ctrl failed\n");
			break;
		}
		
		ret = true;
	} while (0);

	if (ctx != NULL)
		EVP_CIPHER_CTX_free(ctx);
		
	return ret;	
}


bool aes_decrypt(uint8_t* in_buf,  size_t in_buf_size, 
				 uint8_t* in_iv,   size_t in_iv_size,
				 uint8_t* in_mac,  size_t in_mac_size,
				 uint8_t* aes_key, size_t aes_key_size, 
				 uint8_t* out_buf, size_t out_buf_size)
{
	if (in_buf == NULL  || in_buf_size == 0 ||
		in_iv == NULL   || in_iv_size != AES_IV_SIZE ||
		in_mac == NULL  || in_mac_size != AES_MAC_SIZE ||
		aes_key == NULL || aes_key_size != AES_KEY_SIZE ||
		out_buf == NULL || out_buf_size < in_buf_size)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}
	
	if (in_buf_size > MAX_CRYPTO_BUFFER_SIZE || out_buf_size > MAX_CRYPTO_BUFFER_SIZE)
	{
		PRINT(ERROR, CRYPTO, "buffer size is too big\n");
		return false;
	}
		
	int len = (int)out_buf_size;
	bool ret = false;
	EVP_CIPHER_CTX* ctx = NULL;

	do {
		
		ctx = EVP_CIPHER_CTX_new();
		if (ctx == NULL)
		{
			PRINT(ERROR, CRYPTO, "EVP_CIPHER_CTX_new failed\n");
			break;
		}
		
		if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, aes_key, in_iv) != 1)
		{
			PRINT(ERROR, CRYPTO, "EVP_DecryptInit_ex failed\n");
			break;
		}
		
		if (EVP_DecryptUpdate(ctx, out_buf, &len, in_buf, (int)in_buf_size) != 1)
		{
			PRINT(ERROR, CRYPTO, "EVP_DecryptUpdate failed\n");
			break;
		}
		
		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_MAC_SIZE, in_mac) != 1)
		{
			PRINT(ERROR, CRYPTO, "EVP_CIPHER_CTX_ctrl failed\n");
			break;
		}

		if (EVP_DecryptFinal_ex(ctx, out_buf + len, &len) != 1)
		{
			PRINT_CRYPTO_ERROR("EVP_DecryptFinal_ex");
			break;
		}
		
		ret = true;
	} while (0);

	if (ctx != NULL)
		EVP_CIPHER_CTX_free(ctx);
		
	return ret;	
}

