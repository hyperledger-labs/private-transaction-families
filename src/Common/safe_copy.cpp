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
 
#ifdef SGX_ENCLAVE
#include "enclave_log.h"
#include <sgx_trts.h>
#else
#include "app_log.h"
#include "memset_s.h"
#endif

#include <string.h>
#include "safe_copy.h"


bool safe_memcpy(void* dst, size_t dst_size, const void* src, size_t num_bytes) 
{
	if (num_bytes == 0)
		return true;
		
	if (dst == NULL || src == NULL || dst_size == 0)
		return false;
	
	if (num_bytes > dst_size)
		return false;
		
	if (dst_size > ONE_GB)
		return false;

#ifdef SGX_ENCLAVE
	if (sgx_is_within_enclave(dst, dst_size) != 1 && sgx_is_outside_enclave(dst, dst_size) != 1)
		return false;
#endif
	
	memcpy(dst, src, num_bytes); // banned api, but we did all the checks...
	
	if (dst_size > num_bytes)
		memset_s(&((char*)dst)[num_bytes], dst_size-num_bytes, 0, dst_size-num_bytes); // clear the rest of the buffer

	return true;
}

int safe_c_memcpy(void* dst, size_t dst_size, const void* src, size_t num_bytes)
{
	return safe_memcpy(dst, dst_size, src, num_bytes) == true ? 0 : 1;
}


bool safe_strncpy(char* dst, size_t dst_size, const char* src, size_t max_num_chars)
{
	if (max_num_chars == 0)
		return true;
		
	if (dst == NULL || src == NULL || dst_size == 0)
		return false;
		
	if (max_num_chars > dst_size)
		return false;
		
	if (dst_size > ONE_GB)
		return false;

#ifdef SGX_ENCLAVE		
	if (sgx_is_within_enclave(dst, dst_size) != 1 && sgx_is_outside_enclave(dst, dst_size) != 1)
		return false;
#endif
		
	strncpy(dst, src, max_num_chars); // banned api, but we did all the checks...
	// if src string is shorter, strncpy will reset the buffer up to max_num_chars
	
	// we know that dst_size >= max_num_chars
	if (dst_size == max_num_chars)
		dst[dst_size-1] = '\0'; // force null terminator at the end (strncpy may leave the string without it), in case the original string didn't have it, it will overrun the last char!
	else // dst_size is bigger
		memset_s(&dst[max_num_chars], dst_size-max_num_chars, 0, dst_size-max_num_chars); // clear the rest of the buffer

	return true;
}

int safe_c_strncpy(char* dst, size_t dst_size, const char* src, size_t max_num_chars)
{
	return safe_strncpy(dst, dst_size, src, max_num_chars) == true ? 0 : 1;
}


void print_byte_array(const void *mem, uint32_t len)
{
    if (mem == NULL || len == 0)
    {
        PRINT(PLAIN, NONE, "\n( null )\n");
        return;
    }
    
    uint8_t* array = (uint8_t*)mem;
    PRINT(PLAIN, NONE, "%u bytes:\n{\n", len);
    
    uint32_t i = 0;
    for(i = 0; i < len - 1; i++)
    {
        PRINT(PLAIN, NONE, "0x%02x, ", array[i]);
        if (i % 8 == 7) 
			PRINT(PLAIN, NONE, "\n");
    }
    
    PRINT(PLAIN, NONE, "0x%02x ", array[i]);
    PRINT(PLAIN, NONE, "\n}\n");
}
