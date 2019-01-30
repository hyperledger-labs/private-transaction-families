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

#include "app_log.h"

#include <string.h>


#ifdef SGX_ENCLAVE
#error this file should not be compiled inside enclave
#endif

// todo - convert all key strings to lowercase

bool save_public_ec_key_to_file(EC_KEY* ec_key, const char* filename)
{	
	FILE* f = NULL;
	char* key_str = NULL;
	bool ret = false;
	const EC_POINT* ec_point = NULL;
	const EC_GROUP* ec_group = NULL;
	
	if (ec_key == NULL || filename == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}
	
	do {
		
		ec_point = EC_KEY_get0_public_key(ec_key);
		if (ec_point == NULL)
		{
			PRINT(ERROR, CRYPTO, "EC_KEY_get0_public_key returned NULL\n");
			break;
		}
		
		ec_group = EC_KEY_get0_group(ec_key);
		if (ec_group == NULL)
		{
			PRINT_CRYPTO_ERROR("EC_KEY_get0_group");
			break;
		}
		
		key_str = EC_POINT_point2hex(ec_group, ec_point, POINT_CONVERSION_COMPRESSED, NULL);
		if (key_str == NULL)
		{
			PRINT_CRYPTO_ERROR("EC_POINT_point2hex");
			break;
		}
		
		if (strnlen(key_str, EC_PUB_HEX_STR_LEN) != EC_PUB_HEX_STR_LEN-1)
		{
			PRINT(INFO, CRYPTO, "public key length is short, %ld instead of %d\n", strnlen(key_str, EC_PUB_HEX_STR_LEN), EC_PUB_HEX_STR_LEN-1);
			//break;
		}
		
		f = fopen(filename, "w");
		if (f == NULL)
		{
			PRINT(ERROR, CRYPTO, "fopen %s failed\n", filename);
			break;
		}
		
		//if (PEM_write_ECPrivateKey(f, ec_key, NULL, NULL, 0, NULL, NULL) == 0)
		
		if (fwrite(key_str, strnlen(key_str, EC_PUB_HEX_STR_LEN)+1, 1, f) != 1)
		{
			PRINT(ERROR, CRYPTO, "fwrite failed\n");
			break;
		}

		ret = true;
	
	} while (0);
	
	if (f != NULL)
		fclose(f);
	
	if (key_str != NULL)
		OPENSSL_free(key_str);
		
	return ret;
}


bool save_private_ec_key_to_file(EC_KEY* ec_key, const char* filename)
{
	FILE* f = NULL;
	bool ret = false;
	const BIGNUM* priv_key = NULL;
	char* key_str = NULL;
	
	if (ec_key == NULL || filename == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}
	
	do {
		
		priv_key = EC_KEY_get0_private_key(ec_key);
		if (priv_key == NULL)
		{
			PRINT_CRYPTO_ERROR("EC_KEY_get0_private_key");
			break;
		}
		
		key_str = BN_bn2hex(priv_key);
		if (key_str == 0)
		{
			PRINT_CRYPTO_ERROR("BN_bn2hex");
			break;
		}
		
		f = fopen(filename, "w");
		if (f == NULL)
		{
			PRINT(ERROR, CRYPTO, "fopen %s failed\n", filename);
			break;
		}
		
		//if (PEM_write_EC_PUBKEY(f, ec_key) == 0)
		
		if (fwrite(key_str, strnlen(key_str, EC_PRIV_HEX_STR_LEN)+1, 1, f) != 1)
		{
			PRINT(ERROR, CRYPTO, "fwrite failed\n");
			break;
		}
		
		ret = true;
		
	} while (0);
	
	if (f != NULL)
		fclose(f);
		
	if (key_str != NULL)
		OPENSSL_free(key_str);
		
	return ret;
}


bool load_public_ec_key_from_file(EC_KEY** pp_ec_key, const char* filename)
{
	FILE* f = NULL;
	public_ec_key_str_t key_str = {0};
	bool ret = false;
	
	if (pp_ec_key == NULL || filename == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}
	
	do {
		
		f = fopen(filename, "r");
		if (f == NULL)
		{
			PRINT(ERROR, CRYPTO, "fopen %s failed\n", filename);
			break;
		}
		
		//*pp_ec_key = PEM_read_ECPrivateKey(f, NULL, NULL, NULL);
		
		if (fread(key_str, 1, sizeof(public_ec_key_str_t)-1, f) < 1)
		{
			PRINT(ERROR, CRYPTO, "fread failed\n");
			break;
		}
		
		if (create_public_ec_key_from_str(pp_ec_key, &key_str) == false)
		{
			PRINT(ERROR, CRYPTO, "create_public_ec_key_from_str failed\n");
			break;
		}
		
		ret = true;
		
	} while (0);

	if (f != NULL)		
		fclose(f);
	
	return ret;
}


bool add_private_ec_key_from_file(EC_KEY* ec_key, const char* filename)
{
	FILE* f = NULL;
	private_ec_key_str_t key_str = {0};
	bool ret = false;
	
	if (ec_key == NULL || filename == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}
	
	do {
		
		//*pp_ec_key = PEM_read_EC_PUBKEY(f, NULL, NULL, NULL);
			
		f = fopen(filename, "r");
		if (f == NULL)
		{
			PRINT(ERROR, CRYPTO, "fopen %s failed\n", filename);
			return false;
		}
		
		if (fread(key_str, 1, sizeof(private_ec_key_str_t)-1, f) < 1)
		{
			PRINT(ERROR, CRYPTO, "fread failed\n");
			break;
		}
		
		if (add_private_ec_key_from_str(ec_key, &key_str) == false)
		{
			PRINT(ERROR, CRYPTO, "add_private_ec_key_from_str failed\n");
			break;
		}
			
		ret = true;
		
	} while(0);
	
	if (f != NULL)
		fclose(f);
		
	memset_s(key_str, sizeof(private_ec_key_str_t), 0, sizeof(private_ec_key_str_t));
	
	return ret;
}
