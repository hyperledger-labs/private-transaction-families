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

#include "Enclave_t.h"

sgx_status_t secure_apply(const uint8_t* serialized_header, uint32_t header_size, const char* nonce, const char* signer_pub_key, 
						  const uint8_t* signature, const uint8_t* payload_hash, const uint8_t* payload, uint32_t payload_size)
{
	(void)serialized_header;
	(void)header_size;
	(void)nonce;
	(void)signer_pub_key;
	(void)signature;
	(void)payload_hash;
	(void)payload;
	(void)payload_size;
	
	return SGX_SUCCESS;
}

uint64_t enclave_client_read(const char* input_buffer, uint32_t* output_size)
{
	(void)input_buffer;
	(void)output_size;
	
	return 0;
}

int enclave_client_get_encrypted_data(uint64_t id, char* output_buffer, uint32_t output_size)
{
	(void)id;
	(void)output_buffer;
	(void)output_size;
	
	return 0;
}
