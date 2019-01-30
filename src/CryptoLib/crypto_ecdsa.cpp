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

bool ecdsa_sign(const uint8_t* data, size_t data_size, EC_KEY* ec_key, ecdsa_bin_signature_t* out_sig)
{
	sha256_data_t digest = {0};
	const BIGNUM *bn_r = NULL;
	const BIGNUM *bn_s = NULL;
	ECDSA_SIG *ecdsa_sig = NULL;
	bool retval = false;
	int bn_r_size = 0;
	int bn_s_size = 0;
	
	if (data == NULL || data_size == 0 || ec_key == NULL || out_sig == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}
	
	if (data_size > MAX_CRYPTO_BUFFER_SIZE)
	{
		PRINT(ERROR, CRYPTO, "buffer size is too big\n");
		return false;
	}
	
	do {
		
		if (SHA256(data, data_size, digest) == NULL) 
		{
			PRINT(ERROR, CRYPTO, "SHA256 failed\n");
			break;;
		}
		
		//PRINT(INFO, CRYPTO, "ecdsa_sign SHA256 diget:\n");
		//print_byte_array(digest, SHA256_DIGEST_LENGTH);		
		
		ecdsa_sig = ECDSA_do_sign(digest, sizeof(sha256_data_t), ec_key);
		if (ecdsa_sig == NULL)
		{
			PRINT(ERROR, CRYPTO, "ECDSA_do_sign failed\n");
			break;
		}
		
		ECDSA_SIG_get0(ecdsa_sig, &bn_r, &bn_s);
		if (bn_r == NULL || bn_s == NULL)
		{
			PRINT(ERROR, CRYPTO, "ECDSA_SIG_get0 failed\n");
			break;
		}
		
		bn_r_size = BN_num_bytes(bn_r);
		if (bn_r_size > ECDSA_BIN_ELEMENT_SIZE)
		{
			PRINT(ERROR, CRYPTO, "bn_r number is too long, %d bytes instead of %d\n", bn_r_size, ECDSA_BIN_ELEMENT_SIZE);
			break;
		}
		
		bn_s_size = BN_num_bytes(bn_s);
		if (bn_s_size > ECDSA_BIN_ELEMENT_SIZE)
		{
			PRINT(ERROR, CRYPTO, "bn_s number is too long, %d bytes instead of %d\n", bn_s_size, ECDSA_BIN_ELEMENT_SIZE);
			break;
		}
		
		memset_s(out_sig, sizeof(ecdsa_bin_signature_t), 0, sizeof(ecdsa_bin_signature_t));
		
		// if the size is 32 bytes, it will start at offset 0, 31 will start in offset 1 (leaving the first byte as 0) etc.
		if (BN_bn2bin(bn_r, &out_sig->r[ECDSA_BIN_ELEMENT_SIZE - bn_r_size]) != bn_r_size)
		{
			PRINT(ERROR, CRYPTO, "BN_bn2bin failed\n");
			break;
		}
		
		if (BN_bn2bin(bn_s, &out_sig->s[ECDSA_BIN_ELEMENT_SIZE - bn_s_size]) != bn_s_size)
		{
			PRINT(ERROR, CRYPTO, "BN_bn2bin failed\n");
			break;
		}
		
		retval = true;
		
	} while(0);
	
	if (ecdsa_sig != NULL)
		ECDSA_SIG_free(ecdsa_sig);
		
	return retval;
}


bool ecdsa_verify(const uint8_t* data, size_t data_size, EC_KEY* ec_key, const ecdsa_bin_signature_t* in_sig)
{
	sha256_data_t digest = {0};
	BIGNUM *bn_r = NULL;
	BIGNUM *bn_s = NULL;
	ECDSA_SIG *ecdsa_sig = NULL;
	bool retval = false;
	int ret = 0;
	
	if (data == NULL || data_size == 0 || ec_key == NULL || in_sig == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}
	
	if (data_size > MAX_CRYPTO_BUFFER_SIZE)
	{
		PRINT(ERROR, CRYPTO, "buffer size is too big\n");
		return false;
	}
		
	do {
		if (SHA256(data, data_size, digest) == NULL) 
		{
			PRINT(ERROR, CRYPTO, "SHA256 failed\n");
			break;
		}

		bn_r = BN_bin2bn(in_sig->r, sizeof(ecdsa_bin_element_t), NULL);
		if (bn_r == NULL)
		{
			PRINT(ERROR, CRYPTO, "BN_bin2bn failed\n");
			break;
		}
		
		bn_s = BN_bin2bn(in_sig->s, sizeof(ecdsa_bin_element_t), NULL);
		if (bn_s == NULL) 
		{
			PRINT(ERROR, CRYPTO, "BN_bin2bn failed\n");
			break;
		}
		
		if (BN_is_zero(bn_r) == 1 || BN_is_zero(bn_s) == 1)
		{
			PRINT(ERROR, CRYPTO, "signature is empty, data is not signed!\n");
			break;
		}
		
		ecdsa_sig = ECDSA_SIG_new();
		if (ecdsa_sig == NULL) 
		{
			PRINT(ERROR, CRYPTO, "ECDSA_SIG_new failed\n");
			break;
		}

		// sets r and s values of ecdsa_sig
		// calling this function transfers the memory management of the values to the ECDSA_SIG object,
		// and therefore the values that have been passed in should not be freed directly after this function has been called
		if (ECDSA_SIG_set0(ecdsa_sig, bn_r, bn_s) != 1) 
		{
			PRINT(ERROR, CRYPTO, "ECDSA_SIG_set0 failed\n");
			break;
		}
		
		bn_r = NULL;
		bn_s = NULL;
		
		ret = ECDSA_do_verify(digest, sizeof(sha256_data_t), ecdsa_sig, ec_key);
		if (ret != 1)
		{
			PRINT_CRYPTO_ERROR("ECDSA_do_verify");
			break;
		}
		
		retval = true;
		
	} while (0);
	
	if (ecdsa_sig != NULL)
		ECDSA_SIG_free(ecdsa_sig);
		
	if (bn_r != NULL)
		BN_clear_free(bn_r);
		
	if (bn_s != NULL)
		BN_clear_free(bn_s);
		
	return retval;
}
