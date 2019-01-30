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
 
#ifndef _SAFE_COPY_H_
#define _SAFE_COPY_H_

#include <stdint.h>

// these definitions are here just because everyone includes this header
#define ONE_KB (1024)
#define ONE_MB (1024*ONE_KB)
#define ONE_GB (1024*ONE_MB)
#define MAX_NETWORK_MSG_SIZE ONE_GB

#ifdef  __cplusplus
extern "C" {
#endif

// if src is shorter, dst will be filled with zeros up to dst_size
bool safe_memcpy(void* dst, size_t dst_size, const void* src, size_t num_bytes); 
int safe_c_memcpy(void* dst, size_t dst_size, const void* src, size_t num_bytes); // 0 on success, 1 on failure

// if src is shorter, dst will be filled with zeros up to dst_size
// if src is longer, dst will have NULL terminator as the last char
bool safe_strncpy(char* dst, size_t dst_size, const char* src, size_t max_num_chars);
int safe_c_strncpy(char* dst, size_t dst_size, const char* src, size_t max_num_chars); // 0 on success, 1 on failure

void print_byte_array(const void *mem, uint32_t len);

#ifdef  __cplusplus
}
#endif

#endif // _SAFE_COPY_H_
