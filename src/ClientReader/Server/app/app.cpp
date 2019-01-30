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
#include <errno.h>
#include <assert.h>

#include "app.h"
#include "app_log.h"

#include "crypto_file_names.h"
#include "server_network.h"

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


int main(int argc, char* argv[])
{	
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	int retval = 1;
	
	(void)argc;
	(void)argv;

	if (load_enclave(&eid) != 0)
	{
		PRINT(ERROR, MAIN, "load_enclave failed\n");
		return 1;
	}
	
#ifdef DEBUG
#ifndef PERFORMANCE
	enable_mem_debug(eid);
#endif
#endif
	
	retval = server_listener(CLIENT_READER_PORT_NUMBER, 1);

#ifdef DEBUG
#ifndef PERFORMANCE
	print_mem_leaks(eid);
#endif
#endif

	status = sgx_destroy_enclave(eid);
	if (status != SGX_SUCCESS)
		PRINT(ERROR, MAIN, "sgx_destroy_enclave error 0x%x\n", status);

	PRINT(INFO, MAIN, "click enter to exit\n");
	getchar();

	return retval;
}
