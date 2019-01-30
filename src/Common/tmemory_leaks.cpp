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
 
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

#include "enclave_log.h"
#include "Enclave_t.h"


#ifdef MEM_DEBUG
void enable_mem_debug()
{
	CRYPTO_set_mem_debug(1);
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
}

void print_mem_leaks()
{
	BIO *err_bio = BIO_new(BIO_s_mem());
	if (err_bio == NULL)
		return;
		
	ERR_print_errors(err_bio);
	
	char* err_data = NULL;
	BIO_get_mem_data(err_bio, &err_data);
	
	if (err_data != NULL)	
		PRINT(INFO, SERVER, "openssl saved errors:\n%s\n", err_data);
	
	BIO_free_all(err_bio);
	
	// some general cleanup	
    ENGINE_cleanup();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    
	BIO *mem_bio = BIO_new(BIO_s_mem());
	if (mem_bio == NULL)
		return;
		
	CRYPTO_mem_leaks(mem_bio);
	
	char* mem_data = NULL;
	long size = BIO_get_mem_data(mem_bio, &mem_data);
	
	if (mem_data != NULL)
	{
		mem_data[size-1] = '\0';	
		PRINT(INFO, SERVER, "openssl memory leaks:\nexpected - 2 chunks from key manager, 5 chunks from this function's memory buffer, and 2 chunks for each TCS used\n%s\n", mem_data);
	}
	
	BIO_free_all(mem_bio);
}

#else // RELEASE

void enable_mem_debug() {};
void print_mem_leaks() {};

#endif // DEBUG

