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
#include "messages.h"
#include "parse_string.h"
#include "memset_s.h"
#include "server_network.h"
#include "ecall_wrapper.h"

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

// Verify message 1 then generate and return message 2 to isv.
int server_proc_msg1(uint32_t ias_socket,
					 uint64_t* p_session_id,
					 const sgx_ra_msg1_t* p_ra_msg1, size_t msg1_size,
					 char** pp_msg2, size_t* p_msg2_size)
{
    sgx_status_t status = SGX_ERROR_UNEXPECTED;
    int ret = 0;
    
    if (p_ra_msg1 == NULL || pp_msg2 == NULL || p_msg2_size == NULL || msg1_size != sizeof(sgx_ra_msg1_t))
    {
		PRINT(ERROR, SERVER, "server_proc_msg1 wrong input parameters\n");
        return -1;
	}

	// call the enclave to process msg1 and get the required msg2 buffer size	
	status = ecall_wrapper(enclave_msg1_phase1, eid, &ret, ias_socket, p_ra_msg1, p_session_id, p_msg2_size);
	if (status != SGX_SUCCESS || ret != 0)
	{
		PRINT(ERROR, SERVER, "enclave_msg1_phase1 failed with status 0x%x, ret %d\n", status, ret);
		return -1;
	}
	
	assert(*p_msg2_size >= sizeof(sgx_ra_msg2_t));
	
	*pp_msg2 = (char*)malloc(*p_msg2_size);
	if (*pp_msg2 == NULL)
	{
		PRINT(ERROR, SERVER, "malloc failed\n");
		return -1;
	}
	memset_s(*pp_msg2, *p_msg2_size, 0, *p_msg2_size);
	
	// call the enclave to process msg1 and get msg2
	status = ecall_wrapper(enclave_msg1_phase2, eid, &ret, p_ra_msg1, *p_session_id, *pp_msg2, *p_msg2_size);
	if (status != SGX_SUCCESS || ret != 0)
	{
		free(*pp_msg2);
		*pp_msg2 = NULL;
		*p_msg2_size = 0;
		PRINT(ERROR, SERVER, "enclave_msg1_phase2 failed with status 0x%x, ret %d\n", status, ret);
		return -1;
	}
		
    return 0;
}

// Process remote attestation message 3
int server_proc_msg3(uint64_t session_id,
					 const sgx_ra_msg3_t* p_msg3, size_t msg3_size,
                     char** pp_msg4, size_t* p_msg4_size)
{
    sgx_status_t status = SGX_ERROR_UNEXPECTED;
    int ret = 0;
    sgx_ra_msg4_t* p_ra_msg4 = NULL;
    
    if (p_msg3 == NULL || msg3_size < sizeof(sgx_ra_msg3_t) || pp_msg4 == NULL || p_msg4_size == NULL)
    {
		PRINT(ERROR, SERVER, "server_proc_msg3 wrong input parameters\n");
        return -1;
	}
    
    p_ra_msg4 = (sgx_ra_msg4_t*)malloc(sizeof(sgx_ra_msg4_t));
    if (p_ra_msg4 == NULL)
	{
		PRINT(ERROR, SERVER, "malloc failed\n");
		return -1;
	}
	memset_s(p_ra_msg4, sizeof(sgx_ra_msg4_t), 0, sizeof(sgx_ra_msg4_t));
	
	// call the enclave to process msg3 and prepare msg4 as response
	status = ecall_wrapper(enclave_msg3, eid, &ret, (const char*)p_msg3, msg3_size, session_id, (char*)p_ra_msg4, (uint32_t)sizeof(sgx_ra_msg4_t));
	if (status != SGX_SUCCESS || ret != 0)
	{
		free(p_ra_msg4);
		PRINT(ERROR, SERVER, "enclave_msg3 failed with status 0x%x, ret %d\n", status, ret);
		return -1;
	}
		
	*pp_msg4 = (char*)p_ra_msg4;
	*p_msg4_size = sizeof(sgx_ra_msg4_t);
    
    return 0;
}


void server_proc_cleanup(uint64_t session_id)
{
	ecall_wrapper(cleanup_session, eid, session_id);
}


void print_usage(char* filename)
{
	printf("usage:\n%s [server-port] [proxy-url proxy-port]\n", filename);
	printf("\twithout any parameters, service will wait for connections on the default port (%d), connection to IAS will be direct\n", SERVER_SYNC_PORT_NUMBER);
	printf("%s -h - prints this info\n", filename);
	printf("%s --help - prints this info\n", filename);
}


int main(int argc, char* argv[])
{	
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	int retval = 1;
	uint16_t local_port = SERVER_SYNC_PORT_NUMBER;
	const char* proxy_url = NULL;
	uint16_t proxy_port = 0;
	bool use_proxy = false;
	
	// todo - check all of possible inputs
	switch (argc)
	{
		case 1:
			PRINT(INFO, MAIN, "no port provided, listening on the default port (%d)\n", local_port);
			PRINT(INFO, MAIN, "no proxy details provided, connection to IAS will be direct\n");
			break;
		
		case 2:
			if (strcmp("-h", argv[1]) == 0 || strcmp("--help", argv[1]) == 0)
			{
				print_usage(argv[0]);
				return 0;
			}
		
			if (str_to_uint16(argv[1], &local_port) == false)
			{
				PRINT(ERROR, MAIN, "error in local port number conversion\n");
				print_usage(argv[0]);
				return 1;
			}
			PRINT(INFO, MAIN, "listening on port %d\n", local_port);
			
			PRINT(INFO, MAIN, "no proxy details provided, connection to IAS will be direct\n");
			
			break;
			
		case 3:
			PRINT(INFO, MAIN, "no port provided, listening on the default port (%d)\n", local_port);
			
			proxy_url = argv[1];
			if (str_to_uint16(argv[2], &proxy_port) == false)
			{
				PRINT(ERROR, MAIN, "error in proxy port number conversion\n");
				print_usage(argv[0]);
				return 1;
			}
			use_proxy = true;
			PRINT(INFO, MAIN, "connections to IAS will use proxy %s:%d\n", proxy_url, proxy_port);
			
			break;
			
		case 4:
			if (str_to_uint16(argv[1], &local_port) == false)
			{
				PRINT(ERROR, MAIN, "error in local port number conversion\n");
				print_usage(argv[0]);
				return 1;
			}
			
			PRINT(INFO, MAIN, "listening on port %d\n", local_port);
			
			proxy_url = argv[2];
			if (str_to_uint16(argv[3], &proxy_port) == false)
			{
				PRINT(ERROR, MAIN, "error in proxy port number conversion\n");
				print_usage(argv[0]);
				return 1;
			}
			use_proxy = true;
			PRINT(INFO, MAIN, "connections to IAS will use proxy %s:%d\n", proxy_url, proxy_port);
			
			break;
			
		default:
			print_usage(argv[0]);
			return 1;
	}
	
	if (load_enclave(&eid) != 0)
	{
		PRINT(ERROR, MAIN, "load_enclave failed\n");
		return 1;
	}
	
	//client_set_proxy_server("proxy.iil.intel.com", 911);
	
	if (use_proxy == true)
	{
		if (client_set_proxy_server(proxy_url, proxy_port) == false)
		{
			PRINT(ERROR, MAIN, "client_set_proxy_server failed\n");
			return 1;
		}
	}
	
#ifdef MEM_DEBUG
	enable_mem_debug(eid);
#endif
	retval = server_listener(local_port, 2);
#ifdef MEM_DEBUG
	print_mem_leaks(eid);
#endif
	
	status = sgx_destroy_enclave(eid);
	if (status != SGX_SUCCESS)
		PRINT(ERROR, MAIN, "sgx_destroy_enclave error 0x%x\n", status);

	PRINT(INFO, MAIN, "click enter to exit\n");
	getchar();

	return retval;
}

