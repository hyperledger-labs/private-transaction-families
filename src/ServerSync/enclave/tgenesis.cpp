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
#include <sgx_tcrypto.h>
#include <sgx_utils.h>
#include <sgx_tseal.h>
#include "tseal_migration_attr.h" // this file is copied from SGX SDK

#include "Enclave_t.h"

#include "ledger_keys.h"
#include "enclave_role.h"
#include "enclave_log.h"
#include "common.h"
#include "config.h" // for admin key
#include "crypto.h"
#include "crypto_enclave.h"
#include "tmemory_debug.h" // only have effect in DEBUG mode

#include <openssl/rand.h>

static uint8_t ias_key_buffer[MAX_IAS_KEY_LEN] = {0};
static char ias_spid_buffer[SPID_BLOB_SIZE] = {0};
static bool certificate_set = false;

static bool create_ledger_ra_ec_key(ledger_base_keys_t* p_ledger_base_keys)
{
	sgx_ecc_state_handle_t ecc_handle;
	
	if (p_ledger_base_keys == NULL)
	{
		PRINT(ERROR, GENESIS, "wrong input parameter\n");
		return false;
	}
	
	sgx_status_t status = sgx_ecc256_open_context(&ecc_handle);
	if (status != SGX_SUCCESS)
	{
		PRINT(ERROR, GENESIS,  "sgx_ecc256_open_context failed with 0x%x\n", status);
		return false;
	}
	
	status = sgx_ecc256_create_key_pair(&p_ledger_base_keys->ra_priv_ec_key, &p_ledger_base_keys->ra_pub_ec_key, ecc_handle);
	if (status != SGX_SUCCESS)
	{
		sgx_ecc256_close_context(ecc_handle);
		PRINT(ERROR, GENESIS,  "sgx_ecc256_create_key_pair failed with 0x%x\n", status);
		return false;
	}
	
	status = sgx_ecc256_close_context(ecc_handle);
	if (status != SGX_SUCCESS)
	{
		PRINT(ERROR, GENESIS,  "sgx_ecc256_close_context failed with 0x%x\n", status);
		return false;
	}
		
	return true;
}


bool create_ledger_key_files(ledger_base_keys_t* p_ledger_base_keys)
{
	ledger_keys_t ledger_keys = {};
	public_ec_key_str_t sign_pub_ec_key_str = {0};
	private_ec_key_str_t sign_priv_ec_key_str = {0};
	sgx_sealed_data_t* seal_blob = NULL;
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	sgx_status_t ret_status = SGX_ERROR_UNEXPECTED;
	bool res = false;
	sgx_attributes_t attribute_mask = {};
    
	
	if (p_ledger_base_keys == NULL)
	{
		PRINT(ERROR, GENESIS, "wrong input parameter\n");
		return false;
	}
	
	do {
		uint32_t seal_blob_size = sgx_calc_sealed_data_size(LEDGER_ADD_STRING_LEN, sizeof(ledger_base_keys_t));
		seal_blob = (sgx_sealed_data_t*)malloc(seal_blob_size);
		if (seal_blob == NULL)
		{
			PRINT(ERROR, GENESIS, "malloc failed\n");
			break;
		}
		
		attribute_mask.flags = TSEAL_DEFAULT_FLAGSMASK;
		attribute_mask.xfrm = 0x0;
		status = sgx_seal_data_ex(SGX_KEYPOLICY_MRENCLAVE, attribute_mask, TSEAL_DEFAULT_MISCMASK,
								  LEDGER_ADD_STRING_LEN, (uint8_t*)LEDGER_ADD_STRING, 
								  sizeof(ledger_base_keys_t), (const uint8_t*)p_ledger_base_keys, 
								  seal_blob_size, seal_blob);
		if (status != SGX_SUCCESS)
		{
			PRINT(ERROR, GENESIS, "sgx_seal_data_ex failed with 0x%x\n", status);
			break;
		}	
		
		ret_status = save_key_to_file(&status, SEALED_LEDGER_KEYS_FILENAME, (uint8_t*)seal_blob, seal_blob_size);
		if (ret_status != SGX_SUCCESS)
		{
			PRINT(ERROR, GENESIS, "save_key_to_file failed with 0x%x\n", ret_status);
			break;
		}
		if (status != SGX_SUCCESS)
		{
			PRINT(ERROR, GENESIS, "save_key_to_file returned 0x%x\n", status);
			break;
		}
				
		ret_status = save_key_to_file(&status, LEDGER_PUBLIC_RA_KEY_FILENAME, (uint8_t*)&p_ledger_base_keys->ra_pub_ec_key, sizeof(sgx_ec256_public_t));
		if (ret_status != SGX_SUCCESS)
		{
			PRINT(ERROR, GENESIS, "save_key_to_file failed with 0x%x\n", ret_status);
			break;
		}
		if (status != SGX_SUCCESS)
		{
			PRINT(ERROR, GENESIS, "save_key_to_file returned 0x%x\n", status);
			break;
		}
		
		// only do this here in order to generate the public data key
		if (generate_ledger_keys_from_kds(p_ledger_base_keys->kds, &ledger_keys) == false)
		{
			PRINT(ERROR, GENESIS, "generate_ledger_keys_from_kds failed\n");
			break;
		}
		
		ret_status = save_key_to_file(&status, LEDGER_PUBLIC_DATA_KEY_FILENAME, (uint8_t*)&ledger_keys.data_pub_ec_key_str, EC_PUB_HEX_STR_LEN);
		if (ret_status != SGX_SUCCESS)
		{
			PRINT(ERROR, GENESIS, "save_key_to_file failed with 0x%x\n", ret_status);
			break;
		}
		if (status != SGX_SUCCESS)
		{
			PRINT(ERROR, GENESIS, "save_key_to_file returned 0x%x\n", status);
			break;
		}
		
		// only do this here in order to generate the public signing key
		if (generate_ledger_sign_keys_from_kds(p_ledger_base_keys->kds, &sign_pub_ec_key_str, &sign_priv_ec_key_str) == false)
		{
			PRINT(ERROR, GENESIS, "generate_ledger_sign_keys_from_kds failed\n");
			break;
		}
		
		ret_status = save_key_to_file(&status, LEDGER_PUBLIC_SIGN_KEY_FILENAME, (uint8_t*)&sign_pub_ec_key_str, EC_PUB_HEX_STR_LEN);
		if (ret_status != SGX_SUCCESS)
		{
			PRINT(ERROR, GENESIS, "save_key_to_file failed with 0x%x\n", ret_status);
			break;
		}
		if (status != SGX_SUCCESS)
		{
			PRINT(ERROR, GENESIS, "save_key_to_file returned 0x%x\n", status);
			break;
		}

		res = true;
		
	} while(0);
	
	// cleanup
	if (seal_blob != NULL)
		free(seal_blob);
		
	memset_s(&ledger_keys, sizeof(ledger_keys_t), 0, sizeof(ledger_keys_t));
	memset_s(&sign_priv_ec_key_str, sizeof(private_ec_key_str_t), 0, sizeof(private_ec_key_str_t));
	
	return res;
}


sgx_status_t seal_ledger_keys(char* kds_str, char* kds_sig_str)
{
	ledger_base_keys_t ledger_base_keys = {};
	sgx_report_t sgx_report = {};
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	sgx_status_t retval = SGX_ERROR_UNEXPECTED;
	unsigned char* kds_buf = NULL;
	long kds_buf_size = 0;
	unsigned char* kds_sig_buf = NULL;
	long kds_sig_buf_size = 0;
	unsigned char* spid_buf = NULL;
	long spid_buf_size = 0;
	EC_KEY* ec_key = NULL;
	
	verify_enclave_role(ROLE_KEYS_GENESIS);
	
	if (kds_str == NULL || kds_sig_str == NULL)
	{
		PRINT(ERROR, GENESIS, "wrong input parameter\n");
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (strnlen(kds_str, KDF32_HEX_KEY_LEN + 1) != KDF32_HEX_KEY_LEN)
	{
		PRINT(ERROR, GENESIS, "KDS length is %ld, expected %d\n", strnlen(kds_str, KDF32_HEX_KEY_LEN + 1), KDF32_HEX_KEY_LEN);
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (strnlen(kds_sig_str, ECDSA_SIG_HEX_LEN + 1) != ECDSA_SIG_HEX_LEN)
	{
		PRINT(ERROR, GENESIS, "KDS signature length is %ld, expected %ld\n", strnlen(kds_sig_str, ECDSA_SIG_HEX_LEN + 1), ECDSA_SIG_HEX_LEN);
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (certificate_set == false)
	{
		PRINT(ERROR, GENESIS, "IAS data was not set\n");
		return SGX_ERROR_UNEXPECTED;
	}
	
	do
	{
		// convert the kds hex string to binary
		kds_buf = OPENSSL_hexstr2buf(kds_str, &kds_buf_size);
		if (kds_buf == NULL)
		{
			PRINT_CRYPTO_ERROR("OPENSSL_hexstr2buf");
			break;
		}
		if (kds_buf_size != KDF32_KEY_SIZE)
		{
			PRINT(ERROR, GENESIS, "KDS binary size is %ld, expected %d\n", kds_buf_size, KDF32_KEY_SIZE);
			break;
		}
		if (safe_memcpy(&ledger_base_keys.kds, sizeof(kdf32_key_t), kds_buf, KDF32_KEY_SIZE) == false)
		{
            PRINT(ERROR, GENESIS, "safe_memcpy failed\n");
            break;
        }
		
		PRINT(INFO, GENESIS, "using the following kds to create the ledger keys:\n");
		print_byte_array(ledger_base_keys.kds, KDF32_KEY_SIZE);
		
		kds_sig_buf = OPENSSL_hexstr2buf(kds_sig_str, &kds_sig_buf_size);
		if (kds_sig_buf == NULL)
		{
			PRINT_CRYPTO_ERROR("OPENSSL_hexstr2buf");
			break;
		}
		if (kds_sig_buf_size != sizeof(ecdsa_bin_signature_t))
		{
			PRINT(ERROR, GENESIS, "KDS signature binary size is %ld, expected %ld\n", kds_sig_buf_size, sizeof(ecdsa_bin_signature_t));
			break;
		}
		if (safe_memcpy(&ledger_base_keys.kds_signature, sizeof(ecdsa_bin_signature_t), kds_sig_buf, kds_sig_buf_size) == false)
		{
            PRINT(ERROR, GENESIS, "safe_memcpy failed\n");
            break;
        }
        
        // now verify the signature
        SignerPubKey admin_public_key = config::get_admin_key();
        if (create_public_ec_key_from_str(&ec_key, (const public_ec_key_str_t*)&admin_public_key) == false)
        {
			PRINT(ERROR, GENESIS, "create_public_ec_key_from_str failed\n");
            break;
		}
        if (ecdsa_verify(ledger_base_keys.kds, sizeof(kdf32_key_t), ec_key, &ledger_base_keys.kds_signature) == false)
        {
			PRINT(ERROR, GENESIS, "KDS signature verification failed\n");
            break;
		}
        				
		// generate key for remote attestation
		if (create_ledger_ra_ec_key(&ledger_base_keys) == false)
		{
			PRINT(ERROR, GENESIS, "create_ledger_ra_ec_key failed\n");
			break;
		}
		
		// get the current enclave svn and save it inside the blob as well
		status = sgx_create_report(NULL, NULL, &sgx_report);
		if (status != SGX_SUCCESS)
		{
			retval = status;
			PRINT(ERROR, GENESIS, "sgx_create_report returned 0x%x\n", status);
			break;
		}
		ledger_base_keys.ledger_svn = sgx_report.body.isv_svn; // sgx_isv_svn_t is uint16_t
		
		if (safe_strncpy((char*)ledger_base_keys.ias_key_str, MAX_IAS_KEY_LEN, (const char*)ias_key_buffer, MAX_IAS_KEY_LEN) == false)
		{
			PRINT(ERROR, CRYPTO, "safe_strncpy failed\n");
			break;
		}
		
		// convert the IAS spid hex string to binary
		spid_buf = OPENSSL_hexstr2buf(ias_spid_buffer, &spid_buf_size);
		if (spid_buf == NULL)
		{
			PRINT_CRYPTO_ERROR("OPENSSL_hexstr2buf");
			break;
		}
		if (spid_buf_size != sizeof(sgx_spid_t))
		{
			PRINT(ERROR, GENESIS, "SPID binary size is %ld, expected %ld\n", spid_buf_size, sizeof(sgx_spid_t));
			break;
		}
		if (safe_memcpy(&ledger_base_keys.ias_spid, sizeof(sgx_spid_t), spid_buf, sizeof(sgx_spid_t)) == false)
		{
            PRINT(ERROR, GENESIS, "safe_memcpy failed\n");
            break;
        }
        
        ledger_base_keys.version = KEYS_SW_VERSION;
		
		// save the required files
		if (create_ledger_key_files(&ledger_base_keys) == false)
		{
			PRINT(ERROR, GENESIS, "create_ledger_key_files failed\n");
			break;
		}
				
		retval = SGX_SUCCESS;
				
	} while(0);
			
	// cleanup
	memset_s(&ledger_base_keys, sizeof(ledger_base_keys_t), 0, sizeof(ledger_base_keys_t));
	
	memset_s(&kds_str, strnlen(kds_str, KDF32_HEX_KEY_LEN + 1), 0, strnlen(kds_str, KDF32_HEX_KEY_LEN + 1));
	
	if (kds_buf != NULL)
		OPENSSL_free(kds_buf);
	if (kds_sig_buf != NULL)
		OPENSSL_free(kds_sig_buf);
	if (ec_key != NULL)
		EC_KEY_free(ec_key);
		
	memset_s(&ias_key_buffer, MAX_IAS_KEY_LEN, 0, MAX_IAS_KEY_LEN);
	
	memset_s(&ias_spid_buffer, SPID_BLOB_SIZE, 0, SPID_BLOB_SIZE);
	if (spid_buf != NULL)
		OPENSSL_free(spid_buf);
	
			
	return retval;
}


uint32_t set_ias_data(char* key_str, char* spid_str)
{
	verify_enclave_role(ROLE_KEYS_GENESIS);
		
	if (strnlen(key_str, MAX_IAS_KEY_LEN) > MAX_IAS_KEY_LEN - 1)
	{
		PRINT(ERROR, IAS, "certificate key length is at least %ld, expected maximum %d\n", strnlen(key_str, MAX_IAS_KEY_LEN), MAX_IAS_KEY_LEN - 1);
		return 1;
	}
	
	if (strnlen(spid_str, SPID_BLOB_SIZE) != SPID_BLOB_SIZE-1)
	{
		PRINT(ERROR, IAS, "spid length is %ld, expected %ld\n", strnlen(spid_str, SPID_BLOB_SIZE), SPID_BLOB_SIZE-1);
		return 1;
	}
	
	if (safe_strncpy((char*)ias_key_buffer, MAX_IAS_KEY_LEN, (const char*)key_str, MAX_IAS_KEY_LEN) == false)
	{
		PRINT(ERROR, IAS, "safe_strncpy failed\n");
		return 1;
	}
	
	if (safe_strncpy(ias_spid_buffer, SPID_BLOB_SIZE, spid_str, SPID_BLOB_SIZE) == false)
	{
		PRINT(ERROR, IAS, "safe_strncpy failed\n");
		return 1;
	}
	
	certificate_set = true;
	
	return 0;
}


