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

#include "enclave_log.h"
#include "enclave_role.h"
#include "ias_session.h"
#include "server_session.h"
#include "common.h"
#include "tmemory_debug.h" // only have effect in DEBUG mode

#include <sgx_tseal.h>
#include <sgx_report.h>
#include <sgx_utils.h>
#include <sgx_thread.h>

#include "Enclave_t.h"

// implemented in sgx_tkey_exchange.lib, needed for the symmetric keys creation
extern sgx_status_t derive_key(
    const sgx_ec256_dh_shared_t* shared_key,
    const char* label,
    uint32_t label_length,
    sgx_ec_key_128bit_t* derived_key);


// Verify message 1 then generate and return message 2 to isv.
int enclave_msg1_phase1(uint32_t ias_socket,
						const sgx_ra_msg1_t *p_msg1,
						uint64_t* p_session_id,
						size_t* output_buffer_size)
{
    bool res = false;
    size_t msg2_size = 0;
    session_t* session = NULL;
    
    verify_enclave_role(ROLE_KEYS_SERVER);
    
    if (p_msg1 == NULL || p_session_id == NULL || output_buffer_size == NULL)
    {
		PRINT(ERROR, SERVER, "wrong parameters!\n");
		return RA_INTERNAL_ERROR;
	}
	
	// allocate a session structure for this client-server session
	session = (session_t*)malloc(sizeof(session_t));
	if (session == NULL)
	{
		PRINT(ERROR, SERVER, "malloc failed\n");
		return RA_INTERNAL_ERROR;
	}
	memset_s((char*)session, sizeof(session_t), 0, sizeof(session_t));
	
	if (safe_memcpy(&session->gid, sizeof(sgx_epid_group_id_t), &p_msg1->gid, sizeof(sgx_epid_group_id_t)) == false)
	{
		PRINT(ERROR, SERVER, "safe_memcpy failed\n");
		free(session);
		return RA_INTERNAL_ERROR;
	}
	
	session->p_ias_session = ias_create_session(ias_socket);
	if (session->p_ias_session == NULL)
	{
		PRINT(ERROR, SERVER, "ias_create_session failed\n");
		free(session);
		return RA_IAS_FAILED;
	}
	
	// todo - add local storage so i don't have to go the the ias every time?
	
	// Get the sig_rl from attestation server using GID.
	res = ias_get_sigrl(session->p_ias_session, session->gid, &session->sig_rl_size, &session->sig_rl);
	if (res == false)
	{
		PRINT(ERROR, SERVER, "ias_get_sigrl failed\n");
		ias_destroy_session(session->p_ias_session);
		free(session);
		return RA_IAS_FAILED;
	}

// todo - check sig_rl_size (not larger than uint32_t - 1GB?)
	
	*p_session_id = add_session(session);
	if (*p_session_id == 0) // error
	{
		PRINT(ERROR, SERVER, "add_session failed\n");
		if (session->sig_rl != NULL)
			free(session->sig_rl);
		ias_destroy_session(session->p_ias_session);
		free(session);
		return RA_INTERNAL_ERROR;
	}
	
	msg2_size = sizeof(sgx_ra_msg2_t) + session->sig_rl_size;
	*output_buffer_size = msg2_size;
	
	return RA_OK;
}


int enclave_msg1_phase2(const sgx_ra_msg1_t *p_msg1,
						uint64_t session_id,
						char* output_buffer, size_t output_size)
{
    sgx_ecc_state_handle_t ecc_state = NULL;
    sgx_status_t status = SGX_SUCCESS;
    int retval = RA_INTERNAL_ERROR;
    sgx_ra_msg2_t* p_ra_msg2 = (sgx_ra_msg2_t*)output_buffer;
    size_t msg2_size = 0;
	session_t* session = NULL;
	
	verify_enclave_role(ROLE_KEYS_SERVER);
	
	session = get_session(session_id);
	if (session == NULL)
	{
		PRINT(ERROR, SERVER, "wrong session id!\n");
		return RA_INTERNAL_ERROR;
	}
		
	do {
		if (p_msg1 == NULL || output_buffer == NULL)
		{
			PRINT(ERROR, SERVER, "wrong parameters!\n");
			break;
		}
		
		if (ledger_keys_manager.keys_ready() == false)
		{
			PRINT(ERROR, SERVER, "ledger keys are not initialized\n\n");
			break;
		}
		
		msg2_size = sizeof(sgx_ra_msg2_t) + session->sig_rl_size;
		if (msg2_size != output_size) // expected to be the same
		{
			PRINT(ERROR, SERVER, "output buffer is %ld bytes while msg2 needs %ld bytes\n", output_size, msg2_size);
			break;
		}
		
		// first phase only used the gid, verify it is still the same
		if (consttime_memequal(&session->gid, &p_msg1->gid, sizeof(sgx_epid_group_id_t)) == 0)
		{
			PRINT(ERROR, SERVER, "msg1 gid have changed!\n");
			break;
		}
			
		memset_s(p_ra_msg2, msg2_size, 0, msg2_size);
		
		// Need to save the client's public ECCDH key to local storage
		if (safe_memcpy(&session->g_a, sizeof(sgx_ec256_public_t), &p_msg1->g_a, sizeof(sgx_ec256_public_t)) == false)
		{
            PRINT(ERROR, SERVER, "safe_memcpy failed\n");
            break;
        }
			
        // Generate the ECCDH key pair
        status = sgx_ecc256_open_context(&ecc_state);
        if (status != SGX_SUCCESS)
        {
            PRINT(ERROR, SERVER, "sgx_ecc256_open_context failed with 0x%x\n", status);
            break;
        }
        
        status = sgx_ecc256_create_key_pair(&session->b, &session->g_b, ecc_state);
        if (status != SGX_SUCCESS)
        {
            PRINT(ERROR, SERVER, "sgx_ecc256_create_key_pair failed with 0x%x\n", status);
            break;
        }

        // Generate the client/server shared secret
        sgx_ec256_dh_shared_t dh_key = {{0}}; // g^ab
        status = sgx_ecc256_compute_shared_dhkey(&session->b, &session->g_a, &dh_key, ecc_state);
        if (status != SGX_SUCCESS)
        {
            PRINT(ERROR, SERVER, "sgx_ecc256_compute_shared_dhkey failed with 0x%x\n", status);
            break;
        }
        
		status = derive_key(&dh_key, "SMK", (uint32_t)(sizeof("SMK") - 1), &session->smk_key);
        if (status != SGX_SUCCESS)
        {
            PRINT(ERROR, SERVER, "derive_key failed\n");
            break;
        }

		status = derive_key(&dh_key, "SK", (uint32_t)(sizeof("SK") - 1), &session->sk_key);
        if (status != SGX_SUCCESS)
        {
            PRINT(ERROR, SERVER, "derive_key failed\n");
            break;
        }

		status = derive_key(&dh_key, "VK", (uint32_t)(sizeof("VK") - 1), &session->vk_key);
        if (status != SGX_SUCCESS)
        {
            PRINT(ERROR, SERVER, "derive_key failed\n");
            break;
        }

        // Assemble MSG2
        if (safe_memcpy(&p_ra_msg2->g_b, sizeof(sgx_ec256_public_t), &session->g_b, sizeof(sgx_ec256_public_t)) == false ||
			safe_memcpy(&p_ra_msg2->spid, sizeof(sgx_spid_t), &ledger_keys_manager.get_ledger_base_keys()->ias_spid, sizeof(sgx_spid_t)) == false)
		{
            PRINT(ERROR, SERVER, "safe_memcpy failed\n");
            break;
        }
        
        p_ra_msg2->quote_type = SGX_UNLINKABLE_SIGNATURE;
        p_ra_msg2->kdf_id = 0x0001; // AES_CMAC_KDF_ID

        // Create gb_ga
        sgx_ec256_public_t gb_ga[2];
        
        if (safe_memcpy(&gb_ga[0], sizeof(sgx_ec256_public_t), &session->g_b, sizeof(sgx_ec256_public_t)) == false ||
			safe_memcpy(&gb_ga[1], sizeof(sgx_ec256_public_t), &session->g_a, sizeof(sgx_ec256_public_t)) == false)
		{
            PRINT(ERROR, SERVER, "safe_memcpy failed\n");
            break;
        }
        
        // Sign gb_ga with ledger's (SP) private key
        status = sgx_ecdsa_sign((uint8_t*)&gb_ga, sizeof(gb_ga),
								(sgx_ec256_private_t*)&ledger_keys_manager.get_ledger_base_keys()->ra_priv_ec_key,
								&p_ra_msg2->sign_gb_ga,
								ecc_state);
        if (status != SGX_SUCCESS)
        {
            PRINT(ERROR, SERVER, "sgx_ecdsa_sign failed with 0x%x\n", status);
            break;
        }

        // Generate the CMAC with smk for [gb||SPID||TYPE||KDF_ID||server_signature(gb,ga)]
        sgx_mac_t mac = {0};
        uint32_t cmac_size = offsetof(sgx_ra_msg2_t, mac);
        status = sgx_rijndael128_cmac_msg(&session->smk_key, (uint8_t*)&p_ra_msg2->g_b, cmac_size, &mac);
        if (status != SGX_SUCCESS)
        {
            PRINT(ERROR, SERVER, "sgx_rijndael128_cmac_msg failed with 0x%x\n", status);
            break;
        }
        
        if (safe_memcpy(&p_ra_msg2->mac, sizeof(sgx_mac_t), mac, sizeof(sgx_mac_t)) == false ||
			safe_memcpy(&p_ra_msg2->sig_rl[0], session->sig_rl_size, session->sig_rl, session->sig_rl_size) == false)
		{
            PRINT(ERROR, SERVER, "safe_memcpy failed\n");
            break;
        }
        p_ra_msg2->sig_rl_size = (uint32_t)session->sig_rl_size;
        
        retval = RA_OK;

    } while(0);

    if (ecc_state != NULL)
    {
        sgx_ecc256_close_context(ecc_state);
    }
    
	if (retval != RA_OK)
	{
		ias_destroy_session(session->p_ias_session);
		free_session(session_id);
	}
    
    return retval;
}


void print_attestation_report(ias_att_report_t* attestation_report)
{
	PRINT(INFO, SERVER, "Atestation Report:\n");
	PRINT(INFO, SERVER, "\tquote status: %d (%s)\n", attestation_report->status, quote_status_strings[attestation_report->status]);
	PRINT(INFO, SERVER, "\trevocation reason: %u\n", attestation_report->revocation_reason);
#ifdef VERIFY_PSE_ATTESTATION
	PRINT(INFO, SERVER, "\tpse_status: %d (%s)\n",  attestation_report->pse_status, pse_status_strings[attestation_report->pse_status]);
#endif
}


void print_enclave_quote(sgx_quote_t *p_quote)
{
	PRINT(INFO, SERVER, "Enclave Quote:\n");
	PRINT(INFO, SERVER, "\tSignature version: %d\n", p_quote->version);
	PRINT(INFO, SERVER, "\tSignature type: %d\n", p_quote->sign_type);
	PRINT(INFO, SERVER, "\tSignature basename: ");
	print_byte_array(p_quote->basename.name, sizeof(p_quote->basename.name));
	
	PRINT(INFO, SERVER, "\n\tqe_svn: 0x%0x\n", p_quote->qe_svn);
	PRINT(INFO, SERVER, "\tpce_svn: 0x%0x\n",p_quote->pce_svn);
	
	PRINT(INFO, SERVER, "Enclave Report Body:\n");
	PRINT(INFO, SERVER, "\tcpu_svn: ");
	print_byte_array(p_quote->report_body.cpu_svn.svn, sizeof(p_quote->report_body.cpu_svn.svn));
	
#ifdef __x86_64__
	PRINT(INFO, SERVER, "\n\tattributes.flags: 0x%0lx\n", p_quote->report_body.attributes.flags);
	PRINT(INFO, SERVER, "\tattributes.xfrm: 0x%0lx\n", p_quote->report_body.attributes.xfrm);
#else
	PRINT(INFO, SERVER, "\tattributes.flags: 0x%0llx\n", p_quote->report_body.attributes.flags);
	PRINT(INFO, SERVER, "\tattributes.xfrm: 0x%0llx\n", p_quote->report_body.attributes.xfrm);
#endif
	PRINT(INFO, SERVER, "\tmr_enclave: ");
	print_byte_array(p_quote->report_body.mr_enclave.m, sizeof(sgx_measurement_t));
	
	PRINT(INFO, SERVER, "\n\tmr_signer: ");
	print_byte_array(p_quote->report_body.mr_signer.m, sizeof(sgx_measurement_t));
	
	PRINT(INFO, SERVER, "\n\tisv_prod_id: 0x%0x\n", p_quote->report_body.isv_prod_id);
	PRINT(INFO, SERVER, "\tisv_svn: 0x%0x\n",p_quote->report_body.isv_svn);
}


// Process remote attestation message 3
int enclave_msg3(const char* input_buffer, size_t input_size,
                 uint64_t session_id,
                 char* output_buffer, size_t output_size)
{
	int retval = RA_INTERNAL_ERROR;
    int ret = 0;
    bool res = false;
    sgx_status_t status = SGX_SUCCESS;

// todo - check input_size
    
    const sgx_ra_msg3_t* p_msg3 = (const sgx_ra_msg3_t*)input_buffer;
    size_t msg3_size = input_size;
    sgx_ra_msg4_t* p_ra_msg4 = (sgx_ra_msg4_t*)output_buffer;
    
    verify_enclave_role(ROLE_KEYS_SERVER);
            
    session_t* session = get_session(session_id);
	if (session == NULL)
	{
		PRINT(ERROR, SERVER, "session not found\n");
		return RA_INTERNAL_ERROR;
    }
    
    if (ledger_keys_manager.keys_ready() == false)
	{
		PRINT(ERROR, SERVER, "ledger keys are not initialized\n\n");
		return RA_INTERNAL_ERROR;
	}
    
    do
    {
		if (p_msg3 == NULL || msg3_size < sizeof(sgx_ra_msg3_t) || output_buffer == NULL || output_size != sizeof(sgx_ra_msg4_t))
		{
			PRINT(ERROR, SERVER, "bad input parameters\n");
			break;
		}
		
        // Compare g_a in message 3 with local g_a.
        ret = consttime_memequal(&session->g_a, &p_msg3->g_a, sizeof(sgx_ec256_public_t));
        if (ret == 0)
        {
            PRINT(ERROR, SERVER, "g_a is not same as in first message\n");
            retval = RA_PROTOCOL_ERROR;
            break;
        }
        
        size_t mac_size = msg3_size - sizeof(sgx_mac_t);
        const uint8_t* p_msg3_cmaced = (const uint8_t*)p_msg3;
        p_msg3_cmaced += sizeof(sgx_mac_t); // skip the first feild in the message - the mac...

        // Verify the message mac using SMK
        sgx_cmac_128bit_tag_t mac = {0};
        status = sgx_rijndael128_cmac_msg(&session->smk_key, p_msg3_cmaced, (uint32_t)mac_size, &mac);
        if(status != SGX_SUCCESS)
        {
            PRINT(ERROR, SERVER, "sgx_rijndael128_cmac_msg failed with 0x%x\n", status);
            break;
        }

        ret = consttime_memequal(&p_msg3->mac, &mac, sizeof(sgx_cmac_128bit_tag_t));
        if (ret == 0)
        {
            PRINT(ERROR, SERVER, "verify cmac failed\n");
            retval = RA_INTEGRITY_FAILED;
            break;
        }

		sgx_quote_t* p_quote = (sgx_quote_t*)p_msg3->quote;
		
        // Check the quote version if needed. Only check the Quote.version field if the enclave
        // identity fields have changed or the size of the quote has changed.  The version may
        // change without affecting the legacy fields or size of the quote structure.
        //if(p_quote->version < ACCEPTED_QUOTE_VERSION)
        //{
        //    PRINT(ERROR, SERVER,"quote version is too old.");
        //    ret = RA_QUOTE_VERSION_ERROR;
        //    break;
        //}

        // Verify the report_data in the Quote matches the expected value.
        // The first 32 bytes of report_data are SHA256 HASH of {g_a|g_b|vk}.
        // The second 32 bytes of report_data are set to zero.
        // This hash comes from tkey_exchange.cpp line 334.
        // todo - purpose? i think it's to make sure this quote/report was created specifically for this session, so it contains a hash of both public keys and a derived key
        sgx_sha_state_handle_t sha_handle = NULL;
		sgx_report_data_t report_data = {0};
    
        status = sgx_sha256_init(&sha_handle);
        if(status != SGX_SUCCESS)
        {
            PRINT(ERROR, SERVER, "sgx_sha256_init failed with 0x%x\n",status);
            break;
        }
        status = sgx_sha256_update((uint8_t*)&session->g_a, sizeof(sgx_ec256_public_t), sha_handle);
        if(status != SGX_SUCCESS)
        {
            PRINT(ERROR, SERVER, "sgx_sha256_update failed with 0x%x\n",status);
            break;
        }
        status = sgx_sha256_update((uint8_t *)&session->g_b, sizeof(sgx_ec256_public_t), sha_handle);
        if(status != SGX_SUCCESS)
        {
            PRINT(ERROR, SERVER, "sgx_sha256_update failed with 0x%x\n",status);
            break;
        }
        status = sgx_sha256_update((uint8_t*)&session->vk_key, sizeof(sgx_key_128bit_t), sha_handle);
        if(status != SGX_SUCCESS)
        {
            PRINT(ERROR, SERVER, "sgx_sha256_update failed with 0x%x\n",status);
            break;
        }
        status = sgx_sha256_get_hash(sha_handle, (sgx_sha256_hash_t*)&report_data);
        if(status != SGX_SUCCESS)
        {
            PRINT(ERROR, SERVER, "sgx_sha256_get_hash failed with 0x%x\n",status);
            break;
        }
        
        ret = consttime_memequal((uint8_t*)&report_data, (uint8_t*)&p_quote->report_body.report_data, sizeof(sgx_report_data_t));
        if (ret == 0)
        {
            PRINT(ERROR, SERVER, "report_data is not the same\n");
            retval = RA_INTEGRITY_FAILED;
            break;
        }
        
        sgx_report_t report = {};
        status = sgx_create_report(NULL, NULL, &report);
        if (status != SGX_SUCCESS)
        {
			PRINT(ERROR, SERVER, "sgx_create_report failed with 0x%x\n", status);
            break;
		}
		
        ret = consttime_memequal(&report.body.mr_enclave, &p_quote->report_body.mr_enclave, sizeof(sgx_measurement_t));
        if (ret == 0)
        {
			retval = RA_MR_ENCLAVE;
			PRINT(ERROR, SERVER, "client and server mr_enclave are different\n");
			break;
		}
		
		ret = consttime_memequal(&report.body.mr_signer, &p_quote->report_body.mr_signer, sizeof(sgx_measurement_t));
        if (ret == 0)
        {
			retval = RA_MR_SIGNER;
			PRINT(ERROR, SERVER, "client and server mr_signer are different\n");
			break;
		}
		
		ret = consttime_memequal(&report.body.isv_svn, &p_quote->report_body.isv_svn, sizeof(sgx_isv_svn_t));
        if (ret == 0)
        {
			retval = RA_ISV_SVN;
			PRINT(ERROR, SERVER, "client and server isv_svn are different\n");
			break;
		}
		
		ret = consttime_memequal(&report.body.isv_prod_id, &p_quote->report_body.isv_prod_id, sizeof(sgx_prod_id_t));
        if (ret == 0)
        {
			retval = RA_ISV_PROD_ID;
			PRINT(ERROR, SERVER, "client and server isv_prod_id are different\n");
			break;
		}
		
		// make sure no debug <--> release communication
		if (report.body.attributes.flags != p_quote->report_body.attributes.flags)
		{
			retval = RA_ENCLAVE_FLAGS;
			PRINT(ERROR, SERVER, "client and server enclave flags are different\n");
			break;
		}
		
		// todo - any other checks required here to verify the remote enclave?

		print_enclave_quote(p_quote);
		
		PRINT(INFO, SERVER, "Platform Services security properties blob:\n\t");
		print_byte_array(p_msg3->ps_sec_prop.sgx_ps_sec_prop_desc, sizeof(p_msg3->ps_sec_prop.sgx_ps_sec_prop_desc));
		
        ias_att_report_t attestation_report = {};
        res = ias_verify_attestation_evidence(session->p_ias_session, p_quote, msg3_size - sizeof(sgx_ra_msg3_t), &p_msg3->ps_sec_prop, &attestation_report);
        if (res == false)
        {
			PRINT(ERROR, SERVER, "ias_verify_attestation_evidence failed\n");
            retval = RA_IAS_FAILED;
            break;
        }

		print_attestation_report(&attestation_report);
		
        msg4_status_t msg4_status = MSG4_OK;
		if (attestation_report.status != IAS_QUOTE_OK)
        {
            msg4_status = MSG4_IAS_QUOTE;
            PRINT(ERROR, SERVER, "attestation report status is %d\n", attestation_report.status);
        }

#ifdef VERIFY_PSE_ATTESTATION
        if (attestation_report.pse_status != IAS_PSE_OK)
        {
            msg4_status = MSG4_IAS_PSE;
            PRINT(ERROR, SERVER, "attestation report pse status is %d\n", attestation_report.pse_status);
        }
#endif	
		memset_s(p_ra_msg4, sizeof(sgx_ra_msg4_t), 0, sizeof(sgx_ra_msg4_t));

        if (msg4_status == MSG4_OK)
        {
			// Attestation passed - encrypt the ledger keys and return the encrypted blob to the client
			uint8_t aes_gcm_zero_iv[SGX_AESGCM_IV_SIZE] = {0};
			
            status = sgx_rijndael128GCM_encrypt(&session->sk_key, // key
						(const unsigned char*)ledger_keys_manager.get_ledger_base_keys(), sizeof(ledger_base_keys_t), // input
						(unsigned char*)&p_ra_msg4->ledger_keys_blob, // output
						&aes_gcm_zero_iv[0], SGX_AESGCM_IV_SIZE, // input iv
						NULL, 0, // input aad
						&p_ra_msg4->aes_gcm_mac); // output mac
			if (status != SGX_SUCCESS)
			{
				PRINT(ERROR, SERVER, "sgx_rijndael128GCM_encrypt failed with 0x%x\n", status);
				break;
			}
        }
        else
        {
			if (attestation_report.platform_info_valid == 1)
			{
				p_ra_msg4->platform_info_valid = 1;
				if (safe_memcpy(&p_ra_msg4->platform_info, sizeof(sgx_platform_info_t), &attestation_report.platform_info, sizeof(sgx_platform_info_t)) == false)
				{
					PRINT(ERROR, SERVER, "safe_memcpy failed\n");
					break;
				}
			}
		}
        
        p_ra_msg4->status = msg4_status;
        
        retval = RA_OK;
        
    } while(0);
    
    ias_destroy_session(session->p_ias_session);
    free_session(session_id);
    
    return retval;
}


void cleanup_session(uint64_t session_id)
{
	verify_enclave_role(ROLE_KEYS_SERVER);
	
	session_t* session = get_session(session_id);
	if (session == NULL)
	{
		PRINT(ERROR, SERVER, "session not found\n");
		return;
    }
    
    ias_destroy_session(session->p_ias_session);
    free_session(session_id);
}
