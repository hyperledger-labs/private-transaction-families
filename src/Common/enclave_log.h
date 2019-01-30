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
 
#ifndef _ENCLAVE_LOG_H_
#define _ENCLAVE_LOG_H_

#include <stdio.h> // for snprintf
#include <sgx_trts.h> // for SGX_CDECL

#include "log_defines.h"

// this function should be defined in the EDL file untrusted part, and implemented outside the enclave
// to disable enclave prints, this function can be implemented empty inside the enclave
extern "C" sgx_status_t SGX_CDECL uprint(int level, const char* str);

// todo - run the code in release mode, make sure no 'illegal' prints are output

#define BUFFER_SIZE 32768
extern __thread char print_buf[BUFFER_SIZE];

// the %c below was required for SIM mode, somehow the combination of thread local storage and snprintf without parameters causes segmentation fault

#if defined DEBUG && !defined PERFORMANCE

#define PRINT(level, source, format, ...) { \
	if (level == ERROR) \
		snprintf(print_buf, BUFFER_SIZE, "(%s %s) [%s:%d]: " format, source, __FUNCTION__, __FILE__, __LINE__, ##__VA_ARGS__); \
	else \
		snprintf(print_buf, BUFFER_SIZE, format "%c", ##__VA_ARGS__, '\0'); \
	uprint(level, (const char*)print_buf); \
}

#else // RELEASE

#define PRINT(level, source, format, ...) { \
	if (level == ERROR) { \
		snprintf(print_buf, BUFFER_SIZE, "(%s %s) [%s:%d]: " format, source, __FUNCTION__, __FILE__, __LINE__, ##__VA_ARGS__); \
		uprint(level, (const char*)print_buf); } \
}

#endif

#endif // _ENCLAVE_LOG_H_
