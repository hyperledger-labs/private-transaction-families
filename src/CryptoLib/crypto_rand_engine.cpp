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

#include <stdint.h>
#include <string.h>
#include <sgx_thread.h>

#include <openssl/rand.h>

#include "crypto.h"
#include "crypto_kdf_strings.h"
#include "safe_copy.h"

#ifdef SGX_ENCLAVE
#include "enclave_log.h"
#else
#include "app_log.h"
#endif

static int kdf_rand_seed(const void *buf, int num);
static int kdf_rand_bytes(unsigned char *buf, int num);
static void kdf_rand_cleanup(void);
static int kdf_rand_status(void);

RAND_METHOD kdf_rand_meth = {
	kdf_rand_seed,
	kdf_rand_bytes,
	kdf_rand_cleanup,
	NULL,      // add
	kdf_rand_bytes,
	kdf_rand_status,
};

// this is for protecting against developer errors, not against attacks...
sgx_thread_t rand_owner_thread = 0;
// this is the second string in the double kdf call, should be set by the caller
const char* g_kdf_key_string = NULL;

static kdf32_key_t base_kds = {0};
static bool base_kds_set = false;

static kdf32_key_t kds_derived_key = {0};
static uint32_t attempts_counter = 1;

static int kdf_rand_seed(const void *buf, int num) // parameters names are OpenSSL prototype, actually should be called with KDS
{
	if (sgx_thread_equal(sgx_thread_self(), rand_owner_thread) != 1)
	{
		PRINT(ERROR, CRYPTO, "only owner thread can access the random engine\n");
		return 0;
	}
	
	if (num != sizeof(kdf32_key_t))
	{
		PRINT(ERROR, CRYPTO, "num seed bytes given is %d and not %ld\n", num, sizeof(kdf32_key_t));
		return 0;
	}
	
	//PRINT(INFO, CRYPTO,  "rand_seed num = %d\n", num);
	//print_byte_array(buf, num);

	safe_memcpy(base_kds, sizeof(kdf32_key_t), buf, num);
	memset_s(kds_derived_key, sizeof(kdf32_key_t), 0, sizeof(kdf32_key_t));
	attempts_counter = 1;
	base_kds_set = true;
	
	return 1;
}


static bool create_next_random_block()
{
	kdf_nonce_t kdf_nonce1 = {0};
	kdf_nonce_t kdf_nonce2 = {0};
	
	// first nonce - the KDS
	safe_memcpy(kdf_nonce1, sizeof(kdf_nonce_t), base_kds, sizeof(kdf32_key_t));
	
	// second nonce - attempts counter
	safe_memcpy(kdf_nonce2, sizeof(kdf_nonce_t), &attempts_counter, sizeof(uint32_t));

	if (derive_32bytes_key_from_double_hmac_sha_256(ECKEY_1ST_DERIVATION_LABEL, kdf_nonce1, g_kdf_key_string, kdf_nonce2, NULL, &kds_derived_key) == false)
	{
		PRINT(ERROR, CRYPTO, "derive_32bytes_key_from_double_hmac_sha_256 failed\n");
		return false;
	}
	
	// prepare for next iteration
	attempts_counter++;
	
	return true;
}


static int kdf_rand_bytes(unsigned char *buf, int num) 
{
	if (sgx_thread_equal(sgx_thread_self(), rand_owner_thread) != 1)
	{
		PRINT(ERROR, CRYPTO, "only owner thread can access the random engine\n");
		return 0;
	}
	
	// we expect to be asked to give exactly KDF32_KEY_SIZE bytes
	if (num != sizeof(kdf32_key_t))
	{
		PRINT(ERROR, CRYPTO, "num bytes requested is %d and not %ld\n", num, sizeof(kdf32_key_t));
		return 0;
	}

	if (base_kds_set == false)
	{
		PRINT(ERROR, CRYPTO, "kdf random engine is not initialized\n");
		return 0;
	}
	
	// generate the pseudo-random data
	if (create_next_random_block() == false)
	{
		PRINT(ERROR, CRYPTO, "create_next_random_block failed\n");
		return 0;
	}

	// copy the pseudo-random to the output buffer
	safe_memcpy(buf, num, kds_derived_key, sizeof(kdf32_key_t));

	//PRINT(INFO, CRYPTO, "rand_bytes num = %d\n", num);
	//print_byte_array(buf, num);

	return 1;
}


static void kdf_rand_cleanup(void)
{
	if (sgx_thread_equal(sgx_thread_self(), rand_owner_thread) != 1)
	{
		PRINT(ERROR, CRYPTO, "only owner thread can access the random engine\n");
		return;
	}
	
	memset_s(base_kds, sizeof(kdf32_key_t), 0, sizeof(kdf32_key_t));
	base_kds_set = false;
	memset_s(kds_derived_key, sizeof(kdf32_key_t), 0, sizeof(kdf32_key_t));
	attempts_counter = 0;
}


static int kdf_rand_status(void) 
{
	if (sgx_thread_equal(sgx_thread_self(), rand_owner_thread) != 1)
	{
		PRINT(ERROR, CRYPTO, "only owner thread can access the random engine\n");
		return false;
	}
	
	//PRINT(INFO, CRYPTO, "rand_status\n");
	return base_kds_set == true; 
}
