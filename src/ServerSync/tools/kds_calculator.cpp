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
 
#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "app_log.h"
#include "memset_s.h"
#include "parse_string.h"
#include "crypto.h"

void print_usage(char* filename)
{
	printf("usage:\n%s BDS SVN [BDS_SVN]\n", filename);
	printf("\tBDS - Base Derivation Secret, the initial secret to start the calculation from\n");
	printf("\tSVN - the target SVN to which the KDS is needed\n");
	printf("\tBDS_SVN - optional SVN where the KDS = BDS, default is %d\n", USHRT_MAX);
}

int main(int argc, char* argv[])
{	
	int retval = 1;
	uint16_t svn = 0; // input svn
	uint16_t bds_svn = USHRT_MAX; // default value
	uint16_t i = 0;
	size_t j = 0;
	char bds_str[KDF32_HEX_KEY_LEN + 1] = {'\0'}; // bds hex string, copy from input
	unsigned char* bds_buf = NULL; // bds converted to byte array
	long bds_buf_size = 0; // bds byte array size
	kdf32_key_t kds = {}; // will be used in the kds derivation loop
	char* kds_str = NULL; // final kds converted back to hex string for output
	
	// parse input parameters
		
	if (argc < 2 || argc > 4)
	{
		print_usage(argv[0]);
		return 1;
	}
	
	if (argc == 2) 
	{
		print_usage(argv[0]);
		
		if ((strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
			return 0;
		else
			return 1;
	}
	
	// argc == 3 || argc == 4
	
	do {
		// copy the BDS from the input to a local buffer
		size_t bds_str_len = strnlen(argv[1], KDF32_HEX_KEY_LEN + 1);
		if (bds_str_len < KDF32_HEX_KEY_LEN)
		{
			PRINT(ERROR, MAIN, "BDS length is wrong, length is %ld, expected %d\n", bds_str_len, KDF32_HEX_KEY_LEN);
			break;
		}
		if (bds_str_len > KDF32_HEX_KEY_LEN)
		{
			PRINT(ERROR, MAIN, "BDS length is wrong, length is longer than %d\n", KDF32_HEX_KEY_LEN);
			break;
		}
		
		if (safe_strncpy(bds_str, KDF32_HEX_KEY_LEN + 1, argv[1], bds_str_len + 1) == false)
		{
			PRINT(ERROR, MAIN, "safe_strncpy failed\n");
			break;
		}
		
		for (j = 0 ; j < KDF32_HEX_KEY_LEN ; j++)
		{
			if (OPENSSL_hexchar2int(bds_str[j]) == -1)
			{
				PRINT(ERROR, CRYPTO, "BDS string is not %d characters hex string (%ld: 0x%x)\n", KDF32_HEX_KEY_LEN, j, bds_str[j]);
				break;
			}
		}
		if (j != KDF32_HEX_KEY_LEN)
			break;
		
		if (str_to_uint16(argv[2], &svn) == false)
		{
			PRINT(ERROR, MAIN, "error in SVN conversion\n");
			break;
		}
		
		if (argc == 4)
		{
			if (str_to_uint16(argv[3], &bds_svn) == false)
			{
				PRINT(ERROR, MAIN, "error in SVN conversion\n");
				break;
			}
			
			if (bds_svn <= svn)
			{
				PRINT(ERROR, MAIN, "BDS_SVN must be bigger than the required KDS SVN\n");
				break;
			}
		}
		
		// convert the bds hex string to binary
		bds_buf = OPENSSL_hexstr2buf(bds_str, &bds_buf_size);
		if (bds_buf == NULL)
		{
			PRINT_CRYPTO_ERROR("OPENSSL_hexstr2buf");
			break;
		}
		if (bds_buf_size != sizeof(kdf32_key_t))
		{
			PRINT(ERROR, MAIN, "BDS binary size is %ld, expected %ld\n", bds_buf_size, sizeof(kdf32_key_t));
			break;
		}

		if (safe_memcpy(&kds, sizeof(kdf32_key_t), bds_buf, bds_buf_size) == false)
		{
			PRINT(ERROR, MAIN, "safe_memcpy failed\n");
			break;
		}
		
		// do the actual work - create the required KDS
		for (i = bds_svn ; i > svn ; i--)
		{
			if (generate_previous_svn_kds(&kds, &kds, (uint16_t)(i-1)) == false)
			{
				PRINT(ERROR, SERVER, "generate_previous_svn_kds failed\n");
				break;
			}
		}
		if (i != svn)
			break;
		
		// convert the KDS to hex string and print it
		kds_str = OPENSSL_buf2hexstr(kds, sizeof(kdf32_key_t));
		if (kds_str == NULL)
		{
			PRINT_CRYPTO_ERROR("OPENSSL_buf2hexstr");
			break;
		}
		
		printf("kds hex string for svn=%d:\n", svn);
		for (size_t j = 0 ; j < strnlen(kds_str, KDF32_HEX_KEY_LEN*2) ; j++) // filter out the separating ':' (12:34:AB...)
			if (kds_str[j] != ':') 
				putc(kds_str[j], stdout);
		printf("\n");
		
		retval = 0;
		
	} while(0);
	
	memset_s(kds, sizeof(kdf32_key_t), 0, sizeof(kdf32_key_t));
	memset_s(bds_str, KDF32_HEX_KEY_LEN+1, 0, KDF32_HEX_KEY_LEN+1);
	
	if (kds_str != NULL)
	{
		memset_s(kds_str, strnlen(kds_str, KDF32_HEX_KEY_LEN*2), 0, strlen(kds_str));
		OPENSSL_free(kds_str);
	}
	if (bds_buf != NULL)
	{
		memset_s(bds_buf, bds_buf_size, 0, bds_buf_size);
		OPENSSL_free(bds_buf);
	}
		
	if (retval == 1)
		print_usage(argv[0]);
	
	return retval;
}


