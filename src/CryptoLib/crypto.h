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
 
#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/ec.h>

#include "crypto_file_names.h"

#ifndef SGX_ENCLAVE // sgx sdk already have memset_s

#endif

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <iostream>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment (lib, "crypt32")

#define ONE_KB (1024)
#define ONE_MB (1024*ONE_KB)
#define ONE_GB (1024*ONE_MB)
#define MAX_NETWORK_MSG_SIZE ONE_GB
inline bool safe_memcpy(void* dst, size_t dst_size, const void* src, size_t num_bytes)
{
	memcpy(dst, src, num_bytes);
	return true;
}
inline bool safe_strncpy(char* dst, size_t dst_size, const char* src, size_t max_num_chars)
{
	strncpy(dst, src, max_num_chars);
	return true;
}
inline errno_t memset_s(void *dest, size_t dummy_count, int c, size_t count)
{
	memset(dest, c, count);
	return 0;
}
#else
#include "memset_s.h"
#include "safe_copy.h"
#endif

// todo - remove all the openssl paraeters from the APIs, instead use strings in all the APIs and convert internally

/* NUMBER DEFINES */

#define TXN_SW_VERSION 0x0001
#define KEYS_SW_VERSION 0x0001

#define MAX_CRYPTO_BUFFER_SIZE ONE_GB

#define DH_SHARED_SIZE	32
#define AES_KEY_SIZE	16
#define AES_MAC_SIZE	16
#define AES_IV_SIZE		12

#define ECDSA_BIN_ELEMENT_SIZE  32 // size of r and s

#define CMAC_KEY_SIZE	16
#define HMAC_KEY_SIZE	32

#define KDF16_KEY_SIZE	CMAC_KEY_SIZE // KDF 16 uses CMAC-AES-128 to generate the 16 bytes key
#define KDF32_KEY_SIZE	HMAC_KEY_SIZE // KDF 32 uses HMAC-SHA-256 to generate the 32 bytes key
#define KDF32_HEX_KEY_LEN (KDF32_KEY_SIZE*2)

#define KDF_NONCE_SIZE	KDF32_KEY_SIZE
#define KDF_LABEL_LEN 	52
#define KDF_PAD_LEN		96

#define EC_KEY_SIZE		32

// ec keys are saved as hex strings, same way as sawtooth
#define EC_PRIV_HEX_STR_LEN ((EC_KEY_SIZE * 2) + 1) // * 2 = in hex string every 4 bits are a char (0-F), 1 = for the terminating NULL
#define EC_PUB_HEX_STR_LEN  (((EC_KEY_SIZE + 1) * 2) + 1) // 1 = 'COMPRESSED' bit (2) and 'Y-bit' (0 or 1), the rest are like the private key, first 2 bytes are always 02 or 03

#define LEDGER_ADDRESS_HEX_LEN 71 // 70 + 1 for '\0'


/* MACRO DEFINES */
//in calls to PRINT need to pass the ->data explicitly, otherwise the entire struct is being passed
#define TYPE_ARRAY(name, type, size) \
	typedef struct { \
		type data[size]; \
		operator type*() { return &data[0]; } \
		operator const type*() const { return &data[0]; } \
	} name ;
	

/* openssl full error stack print */
#define PRINT_CRYPTO_ERROR(func_name) \
				{ const char* filename; int line; unsigned long err;\
				  PRINT(ERROR, CRYPTO, "%s failed, OpenSSL errors:\n", func_name); \
				  while ((err = ERR_get_error_line(&filename, &line)) != 0) { \
				  PRINT(ERROR, CRYPTO, "filename %s, line %d, error 0x%lx\n", filename, line, err); } }


/* ARRAY TYPES */

TYPE_ARRAY(ledger_hex_address_t, char, LEDGER_ADDRESS_HEX_LEN)

TYPE_ARRAY(private_ec_key_str_t, char, EC_PRIV_HEX_STR_LEN)
TYPE_ARRAY(public_ec_key_str_t, char, EC_PUB_HEX_STR_LEN)

TYPE_ARRAY(ecdsa_bin_element_t, uint8_t, ECDSA_BIN_ELEMENT_SIZE)

TYPE_ARRAY(sha256_data_t, uint8_t, SHA256_DIGEST_LENGTH)
TYPE_ARRAY(sha512_data_t, uint8_t, SHA512_DIGEST_LENGTH)

TYPE_ARRAY(kdf32_key_t, uint8_t, KDF32_KEY_SIZE)
TYPE_ARRAY(kdf16_key_t, uint8_t, KDF16_KEY_SIZE)
TYPE_ARRAY(kdf_nonce_t, uint8_t, KDF_NONCE_SIZE)

TYPE_ARRAY(dh_shared_secret_t, uint8_t, DH_SHARED_SIZE)


/* STRUCTURES */

#pragma pack(1)

typedef struct _kdf_record_data_t {
	sha256_data_t transaction_nonce_hash;
	sha256_data_t address_hash;
} kdf_record_data_t;

typedef struct _kdf_input_t {
	uint32_t	index; // 1
	char		label[KDF_LABEL_LEN];
	uint32_t	separator; // 0
	kdf_nonce_t	nonce;
	union {
		kdf_record_data_t record_data;	// only used for aes-siv key
		uint8_t padding[KDF_PAD_LEN]; // general case, all zeros, also pads 32 bytes if record_data is used
	};
	uint32_t	output_len; // in bits (256)
} kdf_input_t; // total size = 4 + 52 + 4 + 32 + 96 + 4 = 192 bytes

typedef struct _ecdsa_bin_signature_t {
	ecdsa_bin_element_t r;
	ecdsa_bin_element_t s;
} ecdsa_bin_signature_t;

#pragma pack()

#define ECDSA_SIG_HEX_LEN (sizeof(ecdsa_bin_signature_t)*2)


/* FUNCTIONS */

/* crypto.cpp */

bool create_new_ec_key_pair(EC_KEY** ec_key);

bool create_public_ec_key_from_str(EC_KEY** pp_ec_key, const public_ec_key_str_t* p_pub_str);
bool add_private_ec_key_from_str(EC_KEY* ec_key, const private_ec_key_str_t* p_priv_str); // adding private key to an existing ec key

bool get_ec_public_key_as_str(EC_KEY* ec_key, public_ec_key_str_t* p_pub_str);
bool get_ec_private_key_as_str(EC_KEY* ec_key, private_ec_key_str_t* p_priv_str);

bool calculate_dh_shared_secret(EC_KEY* local_key_pair, EC_KEY* remote_public_key, dh_shared_secret_t* dh_shared_secret);

bool get_random_bytes(unsigned char* buf, int num);

#ifndef SGX_ENCLAVE
/* crypto_files.cpp */
// files are using hex string format - to be sawtooth compliant
bool save_public_ec_key_to_file(EC_KEY* ec_key, const char* filename);
bool save_private_ec_key_to_file(EC_KEY* ec_key, const char* filename);
bool load_public_ec_key_from_file(EC_KEY** pp_ec_key, const char* filename); // create new ec key
bool add_private_ec_key_from_file(EC_KEY* ec_key, const char* filename);
#endif

/* crypto_aes.cpp */
bool aes_encrypt(uint8_t* in_buf, size_t in_buf_size, 
				 uint8_t* aes_key, size_t aes_key_size, 
				 uint8_t* out_iv, size_t out_iv_size, // iv is randomize inside this function
				 uint8_t* out_buf, size_t out_buf_size,
				 uint8_t* out_mac, size_t out_mac_size);
				 
bool aes_decrypt(uint8_t* in_buf, size_t in_buf_size, 
				 uint8_t* in_iv, size_t in_iv_size,
				 uint8_t* in_mac, size_t in_mac_size,
				 uint8_t* aes_key, size_t aes_key_size, 
				 uint8_t* out_buf, size_t out_buf_size);
				
/* crypto_hash.cpp */ 
bool sha256_msg(const uint8_t* data, size_t data_size, sha256_data_t* out_hash);
bool sha512_msg(const uint8_t* data, size_t data_size, sha512_data_t* out_hash);
// key_size and out_mac_size must be CMAC_KEY_SIZE
bool cmac_msg(const uint8_t* key, size_t key_size, const void* msg, size_t msg_size, uint8_t* out_mac, size_t out_mac_size);				 


/* crypto_ecdsa.cpp */
bool ecdsa_sign(const uint8_t* data, size_t data_size, EC_KEY* ec_key, ecdsa_bin_signature_t* out_sig);
bool ecdsa_verify(const uint8_t* data, size_t data_size, EC_KEY* ec_key, const ecdsa_bin_signature_t* in_sig);

/* crypto_kdf.cpp */
// uses cmac over aes128_cbc
bool derive_16bytes_key_from_double_cmac_aes_128(const char* label1, kdf_nonce_t nonce1, const char* label2, kdf_nonce_t nonce2, kdf16_key_t* out_key);
// uses hmac over sha256
bool derive_32bytes_key_from_double_hmac_sha_256(const char* label1, kdf_nonce_t nonce1, // input to first hmac
												 const char* label2, kdf_nonce_t nonce2, kdf_record_data_t* p_record_data, // input to second hmac
												 kdf32_key_t* out_key); // output
bool generate_previous_svn_kds(const kdf32_key_t* p_cur_kds, kdf32_key_t* p_prev_kds, uint16_t svn);


#endif // _CRYPTO_H_
