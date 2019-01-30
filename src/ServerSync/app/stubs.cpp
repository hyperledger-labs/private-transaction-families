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

#include "Enclave_u.h"

int tl_call_stl_read(uint32_t* id, const char* addr, char* value, uint32_t data_size)
{
	(void)id;
	(void)addr;
	(void)value;
	(void)data_size;
	
	return 0;
}

int tl_call_stl_read_prefix(uint32_t* id, const char* addr_prefix, char* value, uint32_t num_of_addr)
{
	(void)id;
	(void)addr_prefix;
	(void)value;
	(void)num_of_addr;
	
	return 0;
}

int tl_call_stl_read_cr(uint32_t* id, const char* addr, char* value, uint32_t data_size)
{
	(void)id;
	(void)addr;
	(void)value;
	(void)data_size;
	
	return 0;
}

sgx_status_t tl_call_stl_write(const char* addr, const char* value, size_t data_size)
{
	(void)addr;
	(void)value;
	(void)data_size;
	
	return SGX_SUCCESS;
}

sgx_status_t tl_call_stl_delete(const char* addresses, size_t num_of_address)
{
	(void)addresses;
	(void)num_of_address;
	
	return SGX_SUCCESS;
}

