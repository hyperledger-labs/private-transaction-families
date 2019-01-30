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
 
 #include <sgx_tkey_exchange.h>
 #include <sgx_utils.h>
 
#include "Enclave_t.h"

#include "ledger_keys.h"
#include "enclave_log.h"
#include "enclave_role.h"
#include "common.h"
#include "config.h" // for admin key

#define _mm_pause() __asm __volatile ("pause");

static sgx_ec256_public_t g_sp_pub_key = {};

// sp_pub_key - the public key of the remote enclave, acquired with the ip from the gossip network, or from the data in the ledger
sgx_status_t enclave_init_ra(sgx_ra_context_t *p_context, sgx_ec256_public_t *p_sp_pub_key)
{
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	
	verify_enclave_role(ROLE_KEYS_CLIENT);
	
	if (p_context == NULL || p_sp_pub_key == NULL)
	{
		PRINT(ERROR, CLIENT, "wrong input parameters\n");
        return SGX_ERROR_INVALID_PARAMETER;
	}
	
	// save it for later check
	if (safe_memcpy(&g_sp_pub_key, sizeof(sgx_ec256_public_t), p_sp_pub_key, sizeof(sgx_ec256_public_t)) == false)
	{
        PRINT(ERROR, CLIENT, "safe_memcpy failed\n");
        return SGX_ERROR_UNEXPECTED;
    }

#if VERIFY_PSE_ATTESTATION
	int busy_retry_times = 10;
	
	do {
		status = sgx_create_pse_session();
		// can't do sleep inside enclave, so try to make some delay
		_mm_pause();
		_mm_pause();
		_mm_pause();
	} while (status == SGX_ERROR_BUSY && busy_retry_times-- > 0);
	if (status != SGX_SUCCESS)
	{
		PRINT(ERROR, CLIENT, "sgx_create_pse_session failed with 0x%x\n", status);
		return status;
	}
	
	status = sgx_ra_init(p_sp_pub_key, 1, p_context); // b_pse = 1, check pse services as well, POET is using it
#else
	status = sgx_ra_init(p_sp_pub_key, 0, p_context); // b_pse = 0, no need for pse services so we don't need to check their validity
#endif
	if (status != SGX_SUCCESS)
	{
		sgx_ra_close(*p_context);
		*p_context = 0;
		PRINT(ERROR, CLIENT, "sgx_ra_init failed with 0x%x\n", status);
	}
	
#if VERIFY_PSE_ATTESTATION
	sgx_close_pse_session();
#endif

	return status;
}


sgx_status_t SGXAPI enclave_ra_close(sgx_ra_context_t context)
{
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	
	verify_enclave_role(ROLE_KEYS_CLIENT);
	
	status = sgx_ra_close(context);
	if (status != SGX_SUCCESS)
		PRINT(ERROR, CLIENT, "sgx_ra_close failed with 0x%x\n", status);
	return status;
}

extern bool create_ledger_key_files(ledger_base_keys_t* ledger_base_keys);


sgx_status_t decrypt_and_seal_ledger_keys(sgx_ra_context_t context,
										  uint8_t* aes_keys_blob, uint32_t blob_size,
										  const sgx_aes_gcm_128bit_tag_t* p_aes_gcm_mac)
{
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	sgx_ec_key_128bit_t sk_key;
	ledger_base_keys_t ledger_base_keys = {};
	sgx_report_t sgx_report = {};
	EC_KEY* ec_key = NULL;
		
	verify_enclave_role(ROLE_KEYS_CLIENT);
	
	if (aes_keys_blob == NULL || p_aes_gcm_mac == NULL)
	{
		PRINT(ERROR, CLIENT, "wrong input parameters\n");
        return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (blob_size != sizeof(ledger_base_keys_t))
	{
		PRINT(ERROR, CLIENT, "blob_size incorrect\n");
		return SGX_ERROR_INVALID_PARAMETER;
	}

	do {
		status = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
		if (status != SGX_SUCCESS)
		{
			PRINT(ERROR, CLIENT, "sgx_ra_get_keys failed with 0x%x\n", status);
			break;
		}

		uint8_t aes_gcm_iv[SGX_AESGCM_IV_SIZE] = {0};
		status = sgx_rijndael128GCM_decrypt(&sk_key,
											aes_keys_blob, sizeof(ledger_base_keys_t),
											(uint8_t*)&ledger_base_keys,
											&aes_gcm_iv[0], SGX_AESGCM_IV_SIZE,
											NULL, 0,
											p_aes_gcm_mac);
		if (status != SGX_SUCCESS)
		{
			PRINT(ERROR, CLIENT, "sgx_rijndael128GCM_decrypt failed with 0x%x\n", status);
			break;
		}
		
		if (consttime_memequal(&g_sp_pub_key, &ledger_base_keys.ra_pub_ec_key, sizeof(sgx_ec256_public_t)) != 1)
		{
			PRINT(ERROR, CLIENT, "unexpected public key!\n");
			status = SGX_ERROR_UNEXPECTED;
			break;
		}
		
		// get the current enclave svn and verify its identical to the one in the blob
		status = sgx_create_report(NULL, NULL, &sgx_report);
		if (status != SGX_SUCCESS)
		{
			PRINT(ERROR, CLIENT, "sgx_create_report failed with 0x%x\n", status);
			break;
		}
		if (sgx_report.body.isv_svn != ledger_base_keys.ledger_svn)
		{
			PRINT(ERROR, CLIENT, "svn in the received blob is different from our svn\n");
			break;
		}
		PRINT(INFO, CLIENT, "received data svn is identical to local (0x%x)\n", sgx_report.body.isv_svn);
		
		if (ledger_base_keys.version != KEYS_SW_VERSION)
		{
			PRINT(ERROR, CLIENT, "unsupported base keys version\n");
			break;
		}
		
		// verify the signature inside the blob we got
        SignerPubKey admin_public_key = config::get_admin_key();
        if (create_public_ec_key_from_str(&ec_key, (public_ec_key_str_t*)&admin_public_key) == false)
        {
			PRINT(ERROR, CLIENT, "create_public_ec_key_from_str failed\n");
            break;
		}
        if (ecdsa_verify(ledger_base_keys.kds, sizeof(kdf32_key_t), ec_key, &ledger_base_keys.kds_signature) == false)
        {
			PRINT(ERROR, CLIENT, "KDS signature verification failed\n");
            break;
		}
		PRINT(INFO, CLIENT, "kds signature verified successfully\n");
		
		if (create_ledger_key_files(&ledger_base_keys) == false)
		{
			PRINT(ERROR, GENESIS,  "create_ledger_key_files failed\n");
			status = SGX_ERROR_UNEXPECTED;
			break;
		}

	} while(0);

	// cleanup
	memset_s(&ledger_base_keys, sizeof(ledger_base_keys_t),0, sizeof(ledger_base_keys_t));
	
	if (ec_key != NULL)
		EC_KEY_free(ec_key);
	
	return status;
}
