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

#include <string.h>

#include <openssl/rand.h>

bool create_new_ec_key_pair(EC_KEY** pp_ec_key)
{
	bool key_created = false;	
	EC_KEY* ec_key = NULL;
	
	if (pp_ec_key == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameter\n");
		return false;
	}
	
	do {

		ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
		if (ec_key == NULL)
		{
			PRINT(ERROR, CRYPTO, "EC_KEY_new_by_curve_name returned NULL\n");
			break;
		}
		
		// generate key pair, based on the curve set
		if (EC_KEY_generate_key(ec_key) != 1)
		{
			PRINT(ERROR, CRYPTO, "EC_KEY_generate_key failed\n");
			break;
		}
		
		*pp_ec_key = ec_key;
		
		key_created = true;
	
	} while (0);
	
	if (key_created == false && ec_key != NULL)
		EC_KEY_free(ec_key);
		
	return key_created;
}


bool create_public_ec_key_from_str(EC_KEY** pp_ec_key, const public_ec_key_str_t* p_pub_str)
{
	bool ret = false;
	EC_KEY* ec_key = NULL;
	EC_POINT* ec_point = NULL;
	EC_GROUP* ec_group = NULL;
	
	if (p_pub_str == NULL || pp_ec_key == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}

	do {

		ec_group = EC_GROUP_new_by_curve_name(NID_secp256k1);
		if (ec_group == NULL)
		{
			PRINT(ERROR, CRYPTO, "EC_GROUP_new_by_curve_name returned NULL\n");
			break;
		}
		
		ec_point = EC_POINT_new(ec_group);
		if (ec_point == NULL)
		{
			PRINT(ERROR, CRYPTO, "EC_POINT_new returned NULL\n");
			break;
		}
		
		if (EC_POINT_hex2point(ec_group, *p_pub_str, ec_point, NULL) == NULL)
		{
			PRINT_CRYPTO_ERROR("EC_POINT_hex2point");
			break;
		}
		
		ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
		if (ec_key == NULL)
		{
			PRINT_CRYPTO_ERROR("EC_KEY_new_by_curve_name");
			break;
		} 
		
		if (EC_KEY_set_public_key(ec_key, ec_point) != 1)
		{
			PRINT_CRYPTO_ERROR("EC_KEY_set_public_key");
			break;
		}
		
		if (EC_KEY_check_key(ec_key) != 1)
		{
			PRINT_CRYPTO_ERROR("EC_KEY_check_key");
			break;
		}
		
		ret = true;
		
	} while(0);
			
	if (ec_group != NULL)
		EC_GROUP_free(ec_group);
		
	if (ec_point != NULL)
		EC_POINT_free(ec_point);
		
	if (ret == true)
	{
		*pp_ec_key = ec_key;
	}
	else
	{
		if (ec_key != NULL)	EC_KEY_free(ec_key);
	}

	return ret;
}


bool add_private_ec_key_from_str(EC_KEY* ec_key, const private_ec_key_str_t* p_priv_str)
{
	BIGNUM* priv_key = NULL;
	bool ret = false;
	
	if (p_priv_str == NULL || ec_key == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}
	
	do {
		
		if (BN_hex2bn(&priv_key, *p_priv_str) == 0)
		{
			PRINT(ERROR, CRYPTO, "BN_hex2bn failed\n");
			break;
		}
			
		if (EC_KEY_set_private_key(ec_key, priv_key) != 1)
		{
			PRINT(ERROR, CRYPTO, "EC_KEY_set_private_key failed\n");
			break;
		}
		
		if (EC_KEY_get0_public_key(ec_key) != NULL)
		{
			if (EC_KEY_check_key(ec_key) != 1)
			{
				PRINT(ERROR, CRYPTO, "EC_KEY_check_key failed\n");
				break;
			}
		}
						
		ret = true;
	} while(0);
		
	if (priv_key != NULL)
		BN_clear_free(priv_key);
		
	return ret;
}


static bool calculate_dh_shared_secret_internal(EC_KEY* local_key_pair, const EC_POINT* remote_public_point, dh_shared_secret_t* dh_shared_secret)
{
	if (local_key_pair == NULL || remote_public_point == NULL || dh_shared_secret == NULL)
		return false;
		
	uint32_t secret_size = EC_GROUP_get_degree(EC_KEY_get0_group(local_key_pair));
	secret_size = (secret_size+7)/8;
	
	if (secret_size > sizeof(dh_shared_secret_t) || secret_size < sizeof(dh_shared_secret_t)/2)
		return false;

	secret_size = ECDH_compute_key(dh_shared_secret, sizeof(dh_shared_secret_t), remote_public_point, local_key_pair, NULL);
	if (secret_size <= sizeof(dh_shared_secret_t)/2)
		return false;
	
	return true;
}


bool calculate_dh_shared_secret(EC_KEY* local_key_pair, EC_KEY* remote_public_key, dh_shared_secret_t* dh_shared_secret)
{
	if (remote_public_key == NULL)
		return false;
		
	return calculate_dh_shared_secret_internal(local_key_pair, EC_KEY_get0_public_key(remote_public_key), dh_shared_secret);
}


bool get_ec_public_key_as_str(EC_KEY* ec_key, public_ec_key_str_t* p_pub_str)
{
	const EC_POINT* ec_point = NULL;
	const EC_GROUP* ec_group = NULL;
	char* key_str = NULL;
	bool retval = false;
	    
	if (ec_key == NULL || p_pub_str == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}
	
	do {
		
		ec_point = EC_KEY_get0_public_key(ec_key);
		if (ec_point == NULL)
		{
			PRINT(ERROR, CRYPTO, "EC_KEY_get0_public_key failed\n");
			break;
		}
		
		ec_group = EC_KEY_get0_group(ec_key);
		if (ec_group == NULL)
		{
			PRINT(ERROR, CRYPTO, "EC_KEY_get0_group failed\n");
			break;
		}
			
		key_str = EC_POINT_point2hex(ec_group, ec_point, POINT_CONVERSION_COMPRESSED, NULL);
		if (key_str == NULL)
		{
			PRINT(ERROR, CRYPTO, "EC_POINT_point2hex failed\n");
			break;
		}
		
		if (strnlen(key_str, EC_PUB_HEX_STR_LEN) != EC_PUB_HEX_STR_LEN-1)
		{
			PRINT(INFO, CRYPTO, "EC_POINT_point2hex returned short string size, %ld instead of %d\n", strnlen(key_str, EC_PUB_HEX_STR_LEN), EC_PUB_HEX_STR_LEN-1);
			//break;
		}
		
		if (safe_memcpy(*p_pub_str, sizeof(public_ec_key_str_t), key_str, strnlen(key_str, EC_PUB_HEX_STR_LEN)+1) == false)
		{
			PRINT(ERROR, CRYPTO, "safe_memcpy failed\n");
			break;
		}
		
		retval = true;
		
	} while(0);
	
	if (key_str != NULL)
		OPENSSL_free(key_str);

    return retval;
}


bool get_ec_private_key_as_str(EC_KEY* ec_key, private_ec_key_str_t* p_priv_str)
{
	const BIGNUM *private_k = NULL;
	char* key_str = NULL;
	bool retval = false;
    
	if (ec_key == NULL || p_priv_str == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}
	
	do {
		
		private_k = EC_KEY_get0_private_key(ec_key);
		if (private_k == NULL)
		{
			PRINT(ERROR, CRYPTO, "EC_KEY_get0_private_key failed\n");
			break;
		}	
		
		key_str = BN_bn2hex(private_k);
		if (key_str == NULL)
		{
			PRINT(ERROR, CRYPTO, "BN_bn2hex failed\n");
			break;
		}
		
		if (safe_memcpy(*p_priv_str, sizeof(private_ec_key_str_t), key_str, strnlen(key_str, EC_PRIV_HEX_STR_LEN)+1) == false)
		{
			PRINT(ERROR, CRYPTO, "safe_memcpy failed\n");
			break;
		}
		
		retval = true;
		
	} while(0);
	
	if (key_str != NULL)
		OPENSSL_free(key_str);
	
    return retval;
}


bool get_random_bytes(unsigned char* buf, int num)
{
	 return RAND_bytes(buf, num) == 1 ? true : false;
}

