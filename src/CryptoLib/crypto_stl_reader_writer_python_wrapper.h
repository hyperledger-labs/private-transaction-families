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
 
#include <string>
#include "crypto_transaction.h"

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
#define EXTERN_DLL __declspec(dllexport)
#else
#define EXTERN_DLL
#endif

#ifndef SGX_ENCLAVE
extern "C"
{
        //used by python generator to encrypt txn payload
		EXTERN_DLL bool encrypt_data(const uint8_t *data, size_t size, uint16_t svn, char **res, const char* p_client_public_key_str, const char *keys_path = NULL);
        //used by pytohn client reader to encrypt request and decrypt respond
		EXTERN_DLL bool encrypt_address(char *address, uint16_t svn, uint64_t &nonce, uint8_t *secret, char **res, const char* p_client_public_key_str, const char* p_client_private_key_str, const char *keys_path);
		EXTERN_DLL char* decrypt_data(const char *input_data, uint16_t svn, uint64_t nonce, uint8_t *secret, secure_data_content_t **out, size_t *data_size, const char *keys_path = NULL);
        // used by python to free memory from above apis
		EXTERN_DLL bool free_mem_response(secure_data_content_t **request_str);
		EXTERN_DLL bool free_mem_request(char **request_str);
}
#endif
