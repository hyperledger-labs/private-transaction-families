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
#include <assert.h>

#include "common.h"
#include "app_log.h"
#include "safe_copy.h"
#include "memset_s.h"

#include "Enclave_u.h"

#define ENCLAVE_NAME "Enclave.signed.so"

sgx_enclave_id_t eid = 0;

int load_enclave(sgx_enclave_id_t* p_eid)
{
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	sgx_launch_token_t token = {0};
	int updated = 0;

	status = sgx_create_enclave(ENCLAVE_NAME, SGX_DEBUG_FLAG, &token, &updated, p_eid, NULL);
	if (status != SGX_SUCCESS)
	{
		PRINT(ERROR, MAIN, "sgx_create_enclave error 0x%x\n", status);
		return 1;
	}
	
	return 0;
}

// todo - review this function again
char* load_file(const char* filename, uint32_t* size)
{
	FILE* f = NULL;

	if (filename == NULL || strnlen(filename, FILENAME_MAX) == 0)
		return NULL;
		
	f = fopen(filename, "r");
	if (f == NULL)
	{
		PRINT(ERROR, GENESIS, "fopen %s failed\n", filename);
		return NULL;
	}
	
	fseek(f, 0, SEEK_END);
	size_t len = ftell(f);
	
	if (len > ONE_GB)
	{
		fclose(f);
		PRINT(ERROR, GENESIS, "file size is too big (size: %ld)\n", len);
		return NULL;
	}
	
	char* buf = (char*)malloc(len + 1);
	if (buf == NULL)
	{
		fclose(f);
		PRINT(ERROR, GENESIS, "malloc failed\n");
		return NULL;
	}
	
	fseek(f, 0, SEEK_SET);
	
	size_t read = fread(buf, 1, len, f);
	
	fclose(f);
	
	if (read != len)
	{
		free(buf);
		PRINT(ERROR, GENESIS, "fread failed\n");
		return NULL;
	}
	buf[len] = '\0';
	*size = (uint32_t)len;
	
	return buf;
}

// todo - review this function again
uint32_t load_ias_data()
{
	char* key_str = NULL;
	uint32_t key_str_size = 0;
	char* spid_str = NULL;
	uint32_t spid_str_size = 0;
	
	sgx_status_t status = SGX_SUCCESS;
	uint32_t ret = -1;
	
	do 
	{		
		key_str = load_file(CERT_KEY_FILE, &key_str_size);
		if (key_str == NULL)
		{
			PRINT(ERROR, GENESIS, "load_file %s failed\n", CERT_KEY_FILE);
			break;
		}
		if (key_str[key_str_size-1] == '\n')
		{
			key_str[key_str_size-1] = '\0';
			spid_str_size -= 1;
		}
		
		spid_str = load_file(SPID_FILE, &spid_str_size);
		if (spid_str == NULL)
		{
			PRINT(ERROR, GENESIS, "load_file %s failed\n", SPID_FILE);
			break;
		}
		if (spid_str[spid_str_size-1] == '\n')
		{
			spid_str[spid_str_size-1] = '\0';
			spid_str_size -= 1;
		}

		status = set_ias_data(eid, &ret, key_str, spid_str);
		if (status != SGX_SUCCESS || ret != 0)
		{
			PRINT(ERROR, GENESIS, "enclvae_set_certificate failed, status 0x%x, ret %d\n", status, ret);
			break;
		}
		
		ret = 0;
		
	} while (0);
	
	if (key_str != NULL)
	{
		memset_s(key_str, key_str_size, 0 , key_str_size);
		free(key_str);
	}
	if (spid_str != NULL)
	{
		memset_s(spid_str, spid_str_size, 0 , spid_str_size);
		free(spid_str);
	}	
	
	return ret;
}


int genesis_init_all(char* input_kds_str, char* input_kds_sig_str)
{
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	uint32_t kds_str_size = 0;
	char* kds_str = NULL;
	uint32_t kds_sig_str_size = 0;
	char* kds_sig_str = NULL;
	
	if (load_ias_data() != 0)
	{
		PRINT(ERROR, GENESIS, "load_ias_data failed\n");
		return 1;
	}
	
	if (input_kds_str != NULL)
	{
		// generate the remote attestation keys and save it with the KDS and IAS data to local file
		status = seal_ledger_keys(eid, &ret, input_kds_str, input_kds_sig_str);
	}
	else
	{
		kds_str = load_file(KDS_FILE, &kds_str_size);
		if (kds_str == NULL)
		{
			PRINT(ERROR, GENESIS, "load_file %s failed\n", KDS_FILE);
			return 1;
		}

		if (kds_str[kds_str_size-1] == '\n')
		{
			kds_str[kds_str_size-1] = '\0';
			kds_str_size -= 1;
		}
		
		kds_sig_str = load_file(KDS_SIG_FILE, &kds_sig_str_size);
		if (kds_sig_str == NULL)
		{
			free(kds_str);
			PRINT(ERROR, GENESIS, "load_file %s failed\n", KDS_SIG_FILE);
			return 1;
		}

		if (kds_sig_str[kds_sig_str_size-1] == '\n')
		{
			kds_sig_str[kds_sig_str_size-1] = '\0';
			kds_sig_str_size -= 1;
		}
		
		// generate the remote attestation keys and save it with the KDS and IAS data to local file
		status = seal_ledger_keys(eid, &ret, kds_str, kds_sig_str);
		
		free(kds_str);
		free(kds_sig_str);
	}

	if (status != SGX_SUCCESS || ret != SGX_SUCCESS)
	{
		PRINT(ERROR, GENESIS, "seal_ledger_keys failed, 0x%x, 0x%x\n", status, ret);
		return 1;
	}
	
	PRINT(INFO, GENESIS, "keys created successfully!\n");
	
	return 0;
}


void print_usage(char* filename)
{
	printf("usage:\n%s [kds kds_signature]\n", filename);
	printf("\tkds and its signature can be given as input or loaded from file\n");
	printf("\tkds should be 256 bits number, given as a 64 characters hex string (1234567890abcdef....)\n");
	printf("\tkds signature should be two 256 bits numbers, given as a 128 characters hex string (1234567890abcdef....)\n");
	printf("\tnote that for a given svn, the previous kds should be 'prev_kds = f(cur_kds)', where f is defined in the full documentation\n");
	printf("%s -h - prints this info\n", filename);
	printf("%s --help - prints this info\n", filename);
	printf("details:\n");
	printf("\tall the input files should be located in a folder named 'genesis_files'\n");
	printf("\tthe following files are expected:\n");
	printf("\t%s - optional, if the kds is not provided as input\n", KDS_FILE);
	printf("\t%s - optional, if the kds signature is not provided as input\n", KDS_SIG_FILE);
	printf("\t%s - ledger's private certificate registered with IAS\n", CERT_FILE);
	printf("\t%s - ledger's private key for the certificate\n", CERT_KEY_FILE);
	printf("\t%s - ledger's IAS provided SPID\n", SPID_FILE);
	printf("\tfor more details about connecting with IAS, please refer to the prerequisites section in:\n");
	printf("\thttps://software.intel.com/en-us/articles/code-sample-intel-software-guard-extensions-remote-attestation-end-to-end-example\n");
}


int main(int argc, char* argv[])
{	
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	char kds_str[KDF32_HEX_KEY_LEN + 1] = {};
	char kds_sig_str[ECDSA_SIG_HEX_LEN + 1] = {};
	int retval = 1;
	
	init_log();
	
	if (argc == 1)
	{
		PRINT(INFO, MAIN, "no input kds, using kds from file\n");
	}
	else if (argc == 2)
	{
		print_usage(argv[0]);
		
		if (strcmp("-h", argv[1]) == 0 || strcmp("--help", argv[1]) == 0)
			return 0;
		
		return 1;
	}
	else if (argc == 3)
	{
		size_t kds_str_len = strnlen(argv[1], KDF32_HEX_KEY_LEN + 1);
		if (kds_str_len > KDF32_HEX_KEY_LEN)
		{
			PRINT(ERROR, MAIN, "kds length is too long\n");
			return 1;
		}
		if (kds_str_len < KDF32_HEX_KEY_LEN)
		{
			PRINT(ERROR, MAIN, "kds length is too short\n");
			return 1;
		}
		
		if (safe_strncpy(kds_str, KDF32_HEX_KEY_LEN + 1, argv[1], kds_str_len + 1) == false)
		{
			PRINT(ERROR, MAIN, "safe_strncpy failed\n");
			return 1;
		}
		
		
		size_t kds_sig_str_len = strnlen(argv[2], ECDSA_SIG_HEX_LEN + 1);
		if (kds_sig_str_len > ECDSA_SIG_HEX_LEN)
		{
			PRINT(ERROR, MAIN, "kds signature length is too long\n");
			return 1;
		}
		if (kds_sig_str_len < ECDSA_SIG_HEX_LEN)
		{
			PRINT(ERROR, MAIN, "kds signature length is too short\n");
			return 1;
		}
		
		if (safe_strncpy(kds_sig_str, ECDSA_SIG_HEX_LEN + 1, argv[2], kds_sig_str_len + 1) == false)
		{
			PRINT(ERROR, MAIN, "safe_strncpy failed\n");
			return 1;
		}
	}
	else
	{
		PRINT(ERROR, MAIN, "too many input parameters\n");
		print_usage(argv[0]);
		return 1;
	}
	

	if (load_enclave(&eid) != 0)
	{
		PRINT(ERROR, MAIN, "load_enclave failed\n");
		return 1;
	}
	
	if (argc == 1)
		retval = genesis_init_all(NULL, NULL);
	else // argc == 3
		retval = genesis_init_all(kds_str, kds_sig_str);
	
	status = sgx_destroy_enclave(eid);
	if (status != SGX_SUCCESS)
		PRINT(ERROR, MAIN, "sgx_destroy_enclave error 0x%x\n", status);

	return retval;
}


