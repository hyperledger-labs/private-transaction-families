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



#include "app.h"
#include "crypto_transaction.h"
#include "server_network.h"
#include "ecall_wrapper.h"
#include "secure_allocator.h"

extern sgx_enclave_id_t eid;

// todo - change this function to return char*, input should be a base64 json string (char*)
// todo - extern "C"

int server_process_request(network_packet_t& packet, const secure::string& input_data, secure::string& output_data)
{
    sgx_status_t status = SGX_ERROR_UNEXPECTED;
	
	if (packet.size < sizeof(secure_data_t)) // should be base64 of this structure - about 33% more
	{
		PRINT(ERROR, SERVER, "wrong input_size, got %ld, expected at least %ld\n", packet.size, sizeof(secure_data_t));
        return -1;
	}

	uint64_t id = 0;
	uint32_t response_size = 0;
	
	// call the enclave to process the request and return the required buffer size
	status = ecall_wrapper(enclave_client_read, eid, &id, input_data.c_str(), &response_size);
	if (status != SGX_SUCCESS || id == 0)
	{
		PRINT(ERROR, SERVER, "enclave_client_read failed with status 0x%x, id %ld\n", status, id);
		return -1;
	}

	output_data.resize(response_size);

	int ret = 0;	
	
	// call the enclave again, this time with the buffer
	status = ecall_wrapper(enclave_client_get_encrypted_data, eid, &ret, id, const_cast<char*>(output_data.c_str()), response_size);

	if (status != SGX_SUCCESS || ret != 0)
	{
		PRINT(ERROR, SERVER, "enclave_client_get_encrypted_data failed with status 0x%x, ret %d\n", status, ret);
		return -1;
	}

    packet.size = response_size;
    return 0;
}
