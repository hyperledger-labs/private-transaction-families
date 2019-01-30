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

#include <string>

#include "app_log.h"
#include "memset_s.h"
#include "parse_string.h"
#include "crypto.h"

// keys path
std::string g_path;


void print_usage(char* filename)
{
	printf("usage:\n%s KDS [keys path]\n", filename);
	printf("\tKDS - Key Derivation Secret\n");
}


bool get_full_file_name(const char* filename, std::string& full_name)
{
	if (g_path.empty() == true) // use default path
	{
		char* home_dir = getenv("HOME");
		if (home_dir == NULL)
		{
			PRINT(ERROR, MAIN, "getenv 'HOME' failed\n");
			return false;
		}
		g_path = home_dir;
		g_path += "/";
		g_path += KEYS_DIR_NAME;	
		g_path += "/";
	}
	
	full_name = g_path + filename;
	
	return true;
}
	

bool load_key_from_files(EC_KEY** ec_key)
{
	std::string full_name;
	if (get_full_file_name(ADMIN_PUBLIC_KEY_FILENAME, full_name) == false)
	{
		PRINT(ERROR, MAIN, "get_full_file_name failed\n");
		return false;
	}
	
	// try to load the local key
	if (load_public_ec_key_from_file(ec_key, full_name.c_str()) == false) 
	{
		PRINT(ERROR, MAIN, "load_public_ec_key_from_file failed\n");
		return false;
	}
	
	if (get_full_file_name(ADMIN_PRIVATE_KEY_FILENAME, full_name) == false)
	{
		PRINT(ERROR, MAIN, "get_full_file_name failed\n");
		return false;
	}
		
	if (add_private_ec_key_from_file(*ec_key, full_name.c_str()) == false)
	{
		PRINT(ERROR, MAIN, "add_private_ec_key_from_file failed\n");
		return false;
	}
	
	return true;
}

int main(int argc, char* argv[])
{	
	int retval = 1;
	char kds_str[KDF32_HEX_KEY_LEN + 1] = {'\0'}; // kds hex string, copy from input
	unsigned char* kds_buf = NULL; // kds converted to byte array
	long kds_buf_size = 0; // kds byte array size
	ecdsa_bin_signature_t kds_signature = {};
	char* kds_signature_str = NULL;
	EC_KEY* ec_key = NULL;
	size_t j = 0;
	
	// parse input parameters
		
	if (argc < 2 || argc > 3)
	{
		print_usage(argv[0]);
		return 1;
	}
	
	if (argc == 2) 
	{
		if ((strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
		{
			print_usage(argv[0]);
			return 0;
		}
	}
	
	// argc == 2 || argc == 3
	
	do {
		
		size_t kds_str_len = strnlen(argv[1], KDF32_HEX_KEY_LEN + 1);
		if (kds_str_len < KDF32_HEX_KEY_LEN)
		{
			PRINT(ERROR, MAIN, "KDS length is wrong, length is %ld, expected %d\n", kds_str_len, KDF32_HEX_KEY_LEN);
			break;
		}
		if (kds_str_len > KDF32_HEX_KEY_LEN)
		{
			PRINT(ERROR, MAIN, "KDS length is wrong, length is longer than %d\n", KDF32_HEX_KEY_LEN);
			break;
		}
		
		if (safe_strncpy(kds_str, KDF32_HEX_KEY_LEN + 1, argv[1], kds_str_len + 1) == false)
		{
			PRINT(ERROR, MAIN, "safe_strncpy failed\n");
			break;
		}
		
		for (j = 0 ; j < KDF32_HEX_KEY_LEN ; j++)
		{
			if (OPENSSL_hexchar2int(kds_str[j]) == -1)
			{
				PRINT(ERROR, CRYPTO, "KDS string is not %d characters hex string (%ld: 0x%x)\n", KDF32_HEX_KEY_LEN, j, kds_str[j]);
				break;
			}
		}
		if (j != KDF32_HEX_KEY_LEN)
			break;
		
		// convert the kds hex string to binary
		kds_buf = OPENSSL_hexstr2buf(kds_str, &kds_buf_size);
		if (kds_buf == NULL)
		{
			PRINT_CRYPTO_ERROR("OPENSSL_hexstr2buf");
			break;
		}
		if (kds_buf_size != sizeof(kdf32_key_t))
		{
			PRINT(ERROR, MAIN, "KDS binary size is %ld, expected %ld\n", kds_buf_size, sizeof(kdf32_key_t));
			break;
		}
		
		if (argc == 3)
			g_path = argv[2];
		
		if (load_key_from_files(&ec_key) == false)
		{
			PRINT(ERROR, MAIN, "load_key_from_files failed\n");
			break;
		}
		
		if (ecdsa_sign(kds_buf, kds_buf_size, ec_key, &kds_signature) == false)
		{
			PRINT(ERROR, MAIN, "ecdsa_sign failed\n");
			break;
		}
				
		kds_signature_str = OPENSSL_buf2hexstr((const unsigned char*)&kds_signature, sizeof(ecdsa_bin_signature_t));
		if (kds_signature_str == NULL)
		{
			PRINT_CRYPTO_ERROR("OPENSSL_buf2hexstr");
			break;
		}
		
		printf("kds signature hex string:\n");
		for (size_t j = 0 ; j < strnlen(kds_signature_str, ECDSA_SIG_HEX_LEN*2) ; j++) // filter out the separating ':' (12:34:AB...)
			if (kds_signature_str[j] != ':') 
				putc(kds_signature_str[j], stdout);
		printf("\n");
		
		retval = 0;
		
	} while(0);
	
	memset_s(kds_str, KDF32_HEX_KEY_LEN+1, 0, KDF32_HEX_KEY_LEN+1);

	if (kds_buf != NULL)
	{
		memset_s(kds_buf, kds_buf_size, 0, kds_buf_size);
		OPENSSL_free(kds_buf);
	}
	
	if (kds_signature_str != NULL)
		OPENSSL_free(kds_signature_str);
		
	if (ec_key != NULL)
		EC_KEY_free(ec_key);
		
	if (retval == 1)
		print_usage(argv[0]);
	
	return retval;
}


