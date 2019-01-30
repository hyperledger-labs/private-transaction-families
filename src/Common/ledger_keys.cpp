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
 
#include <sgx_tseal.h>
#include <sgx_utils.h>
#include <sgx_thread.h>
#include <sgx_report.h>

#include <stdio.h>
#include <string.h>

#include "ledger_keys.h"
#include "enclave_log.h"
#include "crypto_enclave.h"
#include "tmemory_debug.h" // only have effect in DEBUG mode

#include "Enclave_t.h"

// todo - move to ledger keys to a separate enclave...

Ledger_Keys_Manager::Ledger_Keys_Manager()
{
	lock = SGX_SPINLOCK_INITIALIZER;
	ledger_keys_array = NULL;
	kds_array = NULL;
	memset_s(&ledger_base_keys, sizeof(ledger_base_keys_t), 0, sizeof(ledger_base_keys_t));
	keys_initialized = false;
}


void Ledger_Keys_Manager::internal_cleanup()
{
	if (ledger_keys_array != NULL)
	{
		memset_s(ledger_keys_array, sizeof(ledger_keys_t) * (ledger_base_keys.ledger_svn + 1), 0, sizeof(ledger_keys_t) * (ledger_base_keys.ledger_svn + 1));
		free(ledger_keys_array);
		ledger_keys_array = NULL;
	}
	
	if (kds_array != NULL)
	{
		memset_s(kds_array, sizeof(kdf32_key_t) * (ledger_base_keys.ledger_svn + 1), 0, sizeof(kdf32_key_t) * (ledger_base_keys.ledger_svn + 1));
		free(kds_array);
		kds_array = NULL;
	}
	
	memset_s(&ledger_base_keys, sizeof(ledger_base_keys_t), 0, sizeof(ledger_base_keys_t));
	keys_initialized = false;
}

Ledger_Keys_Manager::~Ledger_Keys_Manager()
{
	internal_cleanup();
}


bool Ledger_Keys_Manager::load_ledger_base_keys()
{
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	sgx_report_t sgx_report = {};
	bool retval = false;
	
	uint32_t decrypted_size = sizeof(ledger_base_keys_t);
	uint8_t add_string[LEDGER_ADD_STRING_LEN + 1] = {0};
	uint32_t add_len = LEDGER_ADD_STRING_LEN;
	
	uint8_t seal_blob[sizeof(sgx_sealed_data_t) + sizeof(ledger_base_keys_t) + LEDGER_ADD_STRING_LEN];
	sgx_sealed_data_t* seal_data = (sgx_sealed_data_t*)seal_blob;

	do {
		uint32_t seal_blob_size = sgx_calc_sealed_data_size(LEDGER_ADD_STRING_LEN, sizeof(ledger_base_keys_t));
		if (seal_blob_size != sizeof(sgx_sealed_data_t) + sizeof(ledger_base_keys_t) + LEDGER_ADD_STRING_LEN)
		{
			break;
		}
				
		ret = read_key_from_file(&status, SEALED_LEDGER_KEYS_FILENAME, (uint8_t*)seal_blob, seal_blob_size);
		if (ret != SGX_SUCCESS || status != SGX_SUCCESS)
		{
			PRINT(ERROR, SERVER, "read_key_from_file failed with ret: 0x%x, status: 0x%x\n", ret, status);
			break;
		}
		
		status = sgx_unseal_data(seal_data, add_string, &add_len, (uint8_t*)&ledger_base_keys, &decrypted_size);
		if (status != SGX_SUCCESS)
		{
			PRINT(ERROR, SERVER,  "sgx_unseal_data failed with 0x%x\n", status);
			break;
		}
		
		if (decrypted_size != sizeof(ledger_base_keys_t))
		{
			PRINT(ERROR, SERVER,  "sealed blob decrypted_size is %d instead of %ld\n", decrypted_size, sizeof(ledger_base_keys_t));
			break;
		}
		
		if (add_len != LEDGER_ADD_STRING_LEN)
		{
			PRINT(ERROR, SERVER,  "sealed blob add len is %d instead of %d\n", add_len, LEDGER_ADD_STRING_LEN);
			break;
		}
		
		if (consttime_memequal(add_string, LEDGER_ADD_STRING, LEDGER_ADD_STRING_LEN) == 0)
		{
			PRINT(ERROR, SERVER,  "sealed blob add string is [%s] and not [%s]\n", add_string, LEDGER_ADD_STRING);
			break;
		}
		
		if (ledger_base_keys.version != KEYS_SW_VERSION)
		{
			PRINT(ERROR, SERVER, "unsupported base keys version\n");
			break;
		}
		
		status = sgx_create_report(NULL, NULL, &sgx_report);
		if (status != SGX_SUCCESS)
		{
			PRINT(ERROR, SERVER, "sgx_create_report returned 0x%x\n", status);
			break;
		}
		
		if (sgx_report.body.isv_svn != ledger_base_keys.ledger_svn)
		{
			PRINT(ERROR, SERVER, "svn mismatch, wrong keys file\n");
			break;
		}
		
		retval = true;
		
	} while(0);
	
	if (retval == false)
		memset_s(&ledger_base_keys, sizeof(ledger_base_keys_t), 0, sizeof(ledger_base_keys_t));
		
	return retval;
}


bool Ledger_Keys_Manager::initialize_keys()
{	
	uint16_t temp_svn = 0;
	
	sgx_spin_lock(&lock);
	if (keys_initialized == true)
	{
		sgx_spin_unlock(&lock);
		return true;
	}
		
	do {
		
		if (load_ledger_base_keys() == false)
		{
			PRINT(ERROR, SERVER, "load_ledger_base_keys failed\n");
			break;
		}
		
		if (generate_ledger_sign_keys_from_kds(ledger_base_keys.kds, &sign_pub_ec_key_str, &sign_priv_ec_key_str) == false)
		{
			PRINT(ERROR, GENESIS, "generate_ledger_sign_keys_from_kds failed\n");
			break;
		}
		
		// now - allocate space for the current keys, and all the past keys, according to the svn
		ledger_keys_array = (ledger_keys_t*)malloc(sizeof(ledger_keys_t) * (ledger_base_keys.ledger_svn + 1));
		if (ledger_keys_array == NULL)
		{
			PRINT(ERROR, SERVER, "malloc failed\n");
			break;
		}
		
		kds_array = (kdf32_key_t*)malloc(sizeof(kdf32_key_t) * (ledger_base_keys.ledger_svn + 1));
		if (kds_array == NULL)
		{
			PRINT(ERROR, SERVER, "malloc failed\n");
			break;
		}
		
		// copy the current kds
		if (safe_memcpy(kds_array[ledger_base_keys.ledger_svn], sizeof(kdf32_key_t), ledger_base_keys.kds, sizeof(kdf32_key_t)) == false)
		{
			PRINT(ERROR, SERVER, "safe_memcpy failed\n");
			break;
		}
		
		// generate past kds and all the keys
		for (temp_svn = ledger_base_keys.ledger_svn ; temp_svn > 0 ; temp_svn--)
		{
			if (generate_ledger_keys_from_kds(kds_array[temp_svn], &ledger_keys_array[temp_svn]) == false)
			{
				PRINT(ERROR, SERVER, "generate_ledger_keys_from_kds failed\n");
				break;
			}
			
			if (generate_previous_svn_kds(&kds_array[temp_svn], &kds_array[temp_svn-1], (uint16_t)(temp_svn-1)) == false)
			{
				PRINT(ERROR, SERVER, "generate_previous_svn_kds failed\n");
				break;
			}
		}
		if (temp_svn != 0) // error
			break;
			
		// generate keys for svn=0
		if (generate_ledger_keys_from_kds(kds_array[temp_svn], &ledger_keys_array[temp_svn]) == false)
		{
			PRINT(ERROR, SERVER, "generate_ledger_keys_from_kds failed\n");
			break;
		}
		
		PRINT(INFO, SERVER, "keys initialized\n");
		
		keys_initialized = true;
	
	} while (false);
	
	if (keys_initialized == false)
		internal_cleanup();
	   
    sgx_spin_unlock(&lock);
    
	return keys_initialized;
}


bool Ledger_Keys_Manager::keys_ready()
{
	if (keys_initialized == false)
	{
		if (initialize_keys() == false)
			return false;
	}
	
	return true;
}


uint16_t Ledger_Keys_Manager::get_svn()
{
	if (keys_initialized == false)
	{
		if (initialize_keys() == false)
			return 0;
	}
	
	return ledger_base_keys.ledger_svn;
}


const ledger_base_keys_t* Ledger_Keys_Manager::get_ledger_base_keys()
{
	if (keys_initialized == false)
	{
		if (initialize_keys() == false)
			return NULL;
	}
	
	return &ledger_base_keys;
}


const ledger_keys_t* Ledger_Keys_Manager::get_current_ledger_keys()
{
	if (keys_initialized == false)
	{
		if (initialize_keys() == false)
			return NULL;
	}
	
	return &ledger_keys_array[ledger_base_keys.ledger_svn];
}


const kdf32_key_t* Ledger_Keys_Manager::get_current_kds()
{
	if (keys_initialized == false)
	{
		if (initialize_keys() == false)
			return NULL;
	}
	
	return &kds_array[ledger_base_keys.ledger_svn];
}


const ledger_keys_t* Ledger_Keys_Manager::get_ledger_keys_by_svn(uint16_t svn)
{
	if (keys_initialized == false)
	{
		if (initialize_keys() == false)
			return NULL;
	}
	
	if (svn > ledger_base_keys.ledger_svn)
	{
		PRINT(ERROR, SERVER, "svn is too big\n");
		return NULL;
	}	
	
	return &ledger_keys_array[svn];
}


const kdf32_key_t* Ledger_Keys_Manager::get_kds_by_svn(uint16_t svn)
{
	if (keys_initialized == false)
	{
		if (initialize_keys() == false)
			return NULL;
	}
	
	if (svn > ledger_base_keys.ledger_svn)
	{
		PRINT(ERROR, SERVER, "svn is too big\n");
		return NULL;
	}	
	
	return &kds_array[svn];
}

const public_ec_key_str_t* Ledger_Keys_Manager::get_public_signing_key()
{
	if (keys_initialized == false)
	{
		if (initialize_keys() == false)
			return NULL;
	}
	
	return &sign_pub_ec_key_str;
}

const private_ec_key_str_t* Ledger_Keys_Manager::get_private_signing_key()
{
	if (keys_initialized == false)
	{
		if (initialize_keys() == false)
			return NULL;
	}
	
	return &sign_priv_ec_key_str;
}

// // single global instance
Ledger_Keys_Manager ledger_keys_manager;
