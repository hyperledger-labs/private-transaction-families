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
#include <unistd.h>

#include "app_log.h"
#include "common.h"
#include "messages.h"
#include "client_network.h"
#include "parse_string.h"

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


void print_attestation_msg(sgx_ra_msg2_t* p_ra_msg2)
{
    if (p_ra_msg2 == NULL)
    {
        PRINT(INFO, NONE, "\t\n( null )\n");
        return;
    }

	PRINT(INFO, NONE, "MSG2 g_b - ");
	print_byte_array(&(p_ra_msg2->g_b), sizeof(p_ra_msg2->g_b));

	PRINT(INFO, NONE, "MSG2 spid - ");
	print_byte_array(&(p_ra_msg2->spid), sizeof(p_ra_msg2->spid));

	PRINT(INFO, NONE, "MSG2 quote_type : %hx\n", p_ra_msg2->quote_type);

	PRINT(INFO, NONE, "MSG2 kdf_id : %hx\n", p_ra_msg2->kdf_id);

	PRINT(INFO, NONE, "MSG2 sign_gb_ga - ");
	print_byte_array(&(p_ra_msg2->sign_gb_ga), sizeof(p_ra_msg2->sign_gb_ga));

	PRINT(INFO, NONE, "MSG2 mac - ");
	print_byte_array(&(p_ra_msg2->mac), sizeof(p_ra_msg2->mac));

	PRINT(INFO, NONE, "MSG2 sig_rl - ");
	print_byte_array(&(p_ra_msg2->sig_rl), p_ra_msg2->sig_rl_size);
}


int client_get_keys(sgx_enclave_id_t eid, const char* server_url, uint16_t server_port)
{
	int retval = 1;
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	
	sgx_ra_msg1_t ra_msg1 = {};
	sgx_ra_msg2_t* p_ra_msg2 = NULL;
	sgx_ra_msg3_t* p_ra_msg3 = NULL;
	sgx_ra_msg4_t* p_ra_msg4 = NULL;
	
	network_packet_t packet = {};
	
	uint32_t size = 0;
	uint16_t type = 0;
	
	uint32_t extended_epid_group_id = 0;
	
	bool context_init = false;
	sgx_ra_context_t context = 0;
	int socket = -1;
	
	uint32_t busy_retry_time = 3;
	
	sgx_ec256_public_t ledger_ra_pub_ec_key = {}; // will be used as g_a in the DH protocol
	
	status = read_key_from_file(LEDGER_PUBLIC_RA_KEY_FILENAME, (uint8_t*)&ledger_ra_pub_ec_key, sizeof(sgx_ec256_public_t));
	if (status != SGX_SUCCESS)
	{
		PRINT(ERROR, CLIENT,  "failed to read public ledger ec key from file, 0x%x\n", status);
		return retval;
	}
	PRINT(INFO, CLIENT,  "read public ledger ec key succeeded\n");
		
	status = sgx_get_extended_epid_group_id(&extended_epid_group_id);
	if (status != SGX_SUCCESS)
	{
		PRINT(ERROR, CLIENT,  "sgx_get_extended_epid_group_id failed, 0x%x\n", status);
		return retval;
	}
	PRINT(INFO, CLIENT,  "sgx_get_extended_epid_group_id succeeded\n");
	
	socket = client_connect_to_server(server_url, server_port);
	if (socket < 0)
	{
		PRINT(ERROR, CLIENT, "failed to connect to server %s:%d\n", server_url, server_port);
		return retval;
	}

	do {
		status = enclave_init_ra(eid, &ret, &context, &ledger_ra_pub_ec_key);
		if (status != SGX_SUCCESS || ret != SGX_SUCCESS)
		{
			PRINT(ERROR, CLIENT,  "enclave_init_ra failed, 0x%x, 0x%x\n", status, ret);
			break;
		}
		context_init = true;
		
		busy_retry_time = 3;
		do
		{
			// this function is declared in sgx_ukey_exchange.h
			status = sgx_ra_get_msg1(context, eid, sgx_ra_get_ga, &ra_msg1);
			if (status != SGX_ERROR_BUSY)
				break;
			sleep(3); // Wait 3s between retries
		} while (status == SGX_ERROR_BUSY && busy_retry_time--);
		if (status != SGX_SUCCESS)
		{
			PRINT(ERROR, CLIENT,  "sgx_ra_get_msg1 failed, 0x%x\n", status);
			break;
		}
		PRINT(INFO, CLIENT,  "sgx_ra_get_msg1 succeeded\n");

// todo - probably remove this, and the makefile SGX_SIM define
#ifdef SGX_SIM
		ra_msg1.gid[3] = 0x0; ra_msg1.gid[2] = 0x0; ra_msg1.gid[1] = 0x6; ra_msg1.gid[0] = 0xdd;
#endif

		PRINT(INFO, CLIENT, "GID: %02x%02x%02x%02x\n", ra_msg1.gid[3], ra_msg1.gid[2], ra_msg1.gid[1], ra_msg1.gid[0]);
		
		packet.type = TYPE_RA_MSG1;
		packet.size = sizeof(sgx_ra_msg1_t);
		packet.ext_data = extended_epid_group_id;
				
		int iret = client_exchange_data_with_server(socket, &packet, (const char*)&ra_msg1, (char**)&p_ra_msg2);
		if (iret != 0)
		{
			PRINT(ERROR, CLIENT,  "ra_network_send_receive for msg1/msg2 failed, %d\n", iret);
			break;
		}
							
		if (packet.type != TYPE_RA_MSG2)
		{
			PRINT(ERROR, CLIENT,  "response type is not TYPE_RA_MSG2, %d\n", type);
			break;
		}
		
		print_attestation_msg(p_ra_msg2);
		
		busy_retry_time = 3;
		do {
			// this function is declared in sgx_ukey_exchange.h
			status = sgx_ra_proc_msg2(context, eid,
									sgx_ra_proc_msg2_trusted,
									sgx_ra_get_msg3_trusted,
									p_ra_msg2,
									(uint32_t)packet.size,
									&p_ra_msg3,
									&size);
		} while (status == SGX_ERROR_BUSY && busy_retry_time-- > 0);
			
		if (status != SGX_SUCCESS || p_ra_msg3 == NULL)
		{
			PRINT(ERROR, CLIENT,  "sgx_ra_proc_msg2 failed, status 0x%x, p_msg3 = 0x%p\n", status, p_ra_msg3);
			if (status == SGX_ERROR_INVALID_SIGNATURE) // give more info on an error we already encountered
			{
				PRINT(ERROR, CLIENT, "this error can be seen if the client's 'ledger remote attestation public key' is not the one used by the server\n");
			}
			break;
		}
		PRINT(INFO, CLIENT,  "sgx_ra_proc_msg2 succeeded, msg3 is %d bytes\n", size);
		
		packet.type = TYPE_RA_MSG3;
		packet.size = size;
		packet.ext_data = extended_epid_group_id;
		
		iret = client_exchange_data_with_server(socket, &packet, (const char*)p_ra_msg3, (char**)&p_ra_msg4);
		if (iret != 0)
		{
			PRINT(ERROR, CLIENT, "ra_network_send_receive for msg3 failed, %d\n", iret);
			break;
		}
		
		if (packet.type != TYPE_RA_MSG4)
		{
			PRINT(ERROR, CLIENT, "response type is not TYPE_RA_MSG4, %d\n", type);
			break;
		}
		
		if (p_ra_msg4->status != 0)
		{
			if (p_ra_msg4->status == MSG4_IAS_QUOTE)
			{
				PRINT(ERROR, CLIENT, "attestation failed, enclave quote is not ok\n");
			}
			else if (p_ra_msg4->status == MSG4_IAS_PSE)
			{
				PRINT(ERROR, CLIENT, "attestation failed, pse manifest is not ok\n");
			}
			else
			{
				PRINT(ERROR, CLIENT, "attestation failed with status %d\n", p_ra_msg4->status);
			}
			
			if (p_ra_msg4->platform_info_valid == 1)
			{
				sgx_update_info_bit_t update_info = {};
				status = sgx_report_attestation_status(&p_ra_msg4->platform_info, 1, &update_info);
				PRINT(ERROR, CLIENT, "sgx_report_attestation_status returned 0x%x, update required:\n\tuCode: %d\n\tCSME FW: %d\n\tPSW: %d\n", 
						status, update_info.ucodeUpdate, update_info.csmeFwUpdate, update_info.pswUpdate);
			}
			break;
		}
		
		status = decrypt_and_seal_ledger_keys(eid, &ret, context, (uint8_t*)&p_ra_msg4->ledger_keys_blob, sizeof(ledger_base_keys_t), &p_ra_msg4->aes_gcm_mac);
		if (status != SGX_SUCCESS || ret != SGX_SUCCESS)
		{
			PRINT(ERROR, CLIENT,  "decrypt_and_seal_ledger_keys failed, 0x%x, 0x%x\n", status, ret);
			break;
		}
		
		PRINT(INFO, CLIENT, "keys provisioned successfully!\n");
		
		retval = 0;
		
	} while(0);
	
	
	// cleanup
	
	if (context_init == true)
	{
		context_init = false;
		status = enclave_ra_close(eid, &ret, context);
		if (status != SGX_SUCCESS || ret != SGX_SUCCESS)
			PRINT(ERROR, CLIENT,  "enclave_ra_close failed, 0x%x, 0x%x\n", status, ret);
	}

	if (p_ra_msg2 != NULL)
	{
		free(p_ra_msg2);
		p_ra_msg2 = NULL;
	}
				
	if (p_ra_msg3 != NULL)
	{
		free(p_ra_msg3);
		p_ra_msg3 = NULL;
	}
		
	if (p_ra_msg4 != NULL)
	{
		free(p_ra_msg4);
		p_ra_msg4 = NULL;
	}
		
	client_disconnect_from_server(socket);	
	
	return retval;
}


void print_usage(char* filename)
{
	printf("usage:\n%s server-url server-port [proxy-url proxy-port]\n", filename);
	printf("%s local - connect to local machine with the default port (%d) and without a proxy\n", filename, SERVER_SYNC_PORT_NUMBER);
	printf("%s -h - prints this info\n", filename);
	printf("%s --help - prints this info\n", filename);
}


int main(int argc, char* argv[])
{	
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	int retval = 1;
	const char* server_url = SERVER_SYNC_SERVER_IP;
	uint16_t server_port = SERVER_SYNC_PORT_NUMBER;
	const char* proxy_url = NULL;
	uint16_t proxy_port = 0;
	bool use_proxy = false;

	switch (argc)
	{
		case 2:
			if (strcmp("local", argv[1]) == 0)
			{
				PRINT(INFO, MAIN, "local execution, connecting to local server (127.0.0.1) without a proxy\n");
				break;
			}
			
			print_usage(argv[0]);
			
			if (strcmp("-h", argv[1]) == 0 || strcmp("--help", argv[1]) == 0)
				return 0;
			
			return 1;
			
		case 5:
			proxy_url = argv[3];
			if (str_to_uint16(argv[4], &proxy_port) == false)
			{
				PRINT(ERROR, MAIN, "error in proxy port number conversion\n");
				print_usage(argv[0]);
				return 1;
			}
			use_proxy = true;
			PRINT(INFO, MAIN, "using proxy %s:%d\n", proxy_url, proxy_port);
			// fall through
			
		case 3:
			server_url = argv[1];
			if (str_to_uint16(argv[2], &server_port) == false)
			{
				PRINT(ERROR, MAIN, "error in server port number conversion\n");
				print_usage(argv[0]);
				return 1;
			}
			PRINT(INFO, MAIN, "connecting to %s:%d\n", server_url, server_port);
			break;
			
		default:
			print_usage(argv[0]);
			return 1;
	};
	
	if (server_port == 0)
	{
		PRINT(ERROR, MAIN, "server port is not a valid number!\n");
		print_usage(argv[0]);
		return 1;
	}
	
	if (use_proxy == true && proxy_port == 0)
	{
		PRINT(ERROR, MAIN, "proxy port is not a valid number!\n");
		print_usage(argv[0]);
		return 1;
	}
	
	if (load_enclave(&eid) != 0)
	{
		PRINT(ERROR, MAIN, "load_enclave failed\n");
		return 1;
	}
	
	if (use_proxy == true)
	{
		if (client_set_proxy_server(proxy_url, proxy_port) == false)
		{
			PRINT(ERROR, MAIN, "client_set_proxy_server failed\n");
			return 1;
		}
	}
	
	retval = client_get_keys(eid, server_url, server_port);	
	
	status = sgx_destroy_enclave(eid);
	if (status != SGX_SUCCESS)
		PRINT(ERROR, MAIN, "sgx_destroy_enclave error 0x%x\n", status);

	PRINT(INFO, MAIN, "click enter to exit\n");
	getchar();

	return retval;
}


