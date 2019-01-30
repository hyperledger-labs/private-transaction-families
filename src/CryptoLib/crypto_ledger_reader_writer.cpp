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
 
#include <stdio.h>
#include <assert.h>
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
#include <direct.h>
#include <string>
static const char slash = '\\';
#else
#include <string.h>
static const char slash = '/';
#endif

#include "crypto.h"
#include "crypto_kdf_strings.h"
#include "crypto_ledger_reader_writer.h"

#ifdef SGX_ENCLAVE
#include "enclave_log.h"
#include "PrivateLedger.h"
#include "acl_read_write.h"
#else // APP
#include "app_log.h"
#include <sys/stat.h>
#include <sys/types.h>

#if defined(HSM_SIGN)
// for release, the txn/request signing should be done by an HSM, 
// this function should be implemented and supply by the client
// the key parameter is probably not needed, and only holds the public key part
extern bool hsm_sign(const uint8_t* data, size_t data_size, char* signer_public_ec_key_str, uint8_t* out_sig_32bytes_r_32bytes_s);
#endif

#endif

// todo - take out all the direct openssl calls and parameters (session key...)

Ledger_Reader_Writer::Ledger_Reader_Writer()
{
	m_keys_initialized = false;
	m_local_ec_key = NULL;
	m_local_sign_ec_key = NULL;
	m_remote_public_ec_key = NULL;
	m_remote_public_sign_ec_key = NULL;
	
	m_svn_initialized = false;
	m_svn = 0;
	
	m_nonce = 0;
	
	m_dh_shared_secret_initialized = false;
	memset_s(&m_dh_shared_secret, sizeof(dh_shared_secret_t), 0, sizeof(dh_shared_secret_t));
}


Ledger_Reader_Writer::Ledger_Reader_Writer(uint64_t nonce, dh_shared_secret_t* dh_shared_secret)
{
	m_keys_initialized = false;
	m_local_ec_key = NULL;
	m_local_sign_ec_key = NULL;
	m_remote_public_ec_key = NULL;
	m_remote_public_sign_ec_key = NULL;
	
	m_svn_initialized = false;
	m_svn = 0;
		
	m_nonce = nonce;
	
	if (safe_memcpy(&m_dh_shared_secret, sizeof(dh_shared_secret_t), dh_shared_secret, sizeof(dh_shared_secret_t)) == true)
		m_dh_shared_secret_initialized = true;
	else
		m_dh_shared_secret_initialized = false; // save me the trouble of error handling in a constructor...
}


void Ledger_Reader_Writer::delete_keys()
{
	m_keys_initialized = false;
	
	if (m_remote_public_ec_key != NULL)
	{
		EC_KEY_free(m_remote_public_ec_key);
		m_remote_public_ec_key = NULL;
	}
	
	if (m_remote_public_sign_ec_key != NULL)
	{
		EC_KEY_free(m_remote_public_sign_ec_key);
		m_remote_public_sign_ec_key = NULL;
	}
	
	if (m_local_ec_key != NULL)
	{
		EC_KEY_free(m_local_ec_key);
		m_local_ec_key = NULL;
	}
	
	if (m_local_sign_ec_key != NULL)
	{
		EC_KEY_free(m_local_sign_ec_key);
		m_local_sign_ec_key = NULL;
	}
}


Ledger_Reader_Writer::~Ledger_Reader_Writer()
{
	delete_keys();
	
	m_svn_initialized = false;
	
	m_dh_shared_secret_initialized = false;
	memset_s(&m_dh_shared_secret, sizeof(dh_shared_secret_t), 0, sizeof(dh_shared_secret_t));
	
	m_nonce = 0;
}


uint64_t Ledger_Reader_Writer::get_nonce()
{
	return m_nonce;
}


bool Ledger_Reader_Writer::get_dh_shared_secret(dh_shared_secret_t* dh_shared_secret)
{
	if (dh_shared_secret == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameter\n");
		return false;
	}
	
	if (m_dh_shared_secret_initialized == false)
	{
		PRINT(ERROR, CRYPTO, "dh_shared_secret is not initialized\n");
		return false;
	}
	
	if (safe_memcpy(dh_shared_secret, sizeof(dh_shared_secret_t), &m_dh_shared_secret, sizeof(dh_shared_secret_t)) == false)
	{
		PRINT(ERROR, CRYPTO, "safe_memcpy failed\n");
		return false;
	}
	
	return true;
}


void Ledger_Reader_Writer::set_svn(uint16_t ledger_svn)
{
	m_svn = ledger_svn;
	m_svn_initialized = true;
}


#ifndef SGX_ENCLAVE
// no try-catch for bad_alloc, this is outside the enclave, let the caller handle it
void Ledger_Reader_Writer::set_files_path(const char* path_name)
{
	m_path = path_name;
	
	if (m_path.back() != slash) // last character
		m_path += slash;
}


bool Ledger_Reader_Writer::get_full_file_name(const char* filename, std::string& full_name)
{
	if (m_path.empty() == true) // use default path
	{
		char* home_dir = getenv("HOME");
		if (home_dir == NULL)
		{
			PRINT(ERROR, CRYPTO, "getenv 'HOME' failed\n");
			return false;
		}
		m_path = home_dir;
		m_path += slash;
		m_path += KEYS_DIR_NAME;
		
		// create the folder if it doesn't exist
		struct stat st = {};
		if (stat(m_path.c_str(), &st) == -1) 
		{
			PRINT(INFO, OCALL, "creating keys directory %s\n", m_path.c_str());
			if (mkdir_cross_OS(m_path.c_str()) != 0)
			{
				PRINT(ERROR, CRYPTO, "mkdir for keys folder failed\n");
				return false;
			}
		}
		
		m_path += slash;
	}
	
	full_name = m_path + filename;
	
	return true;
}
	
int Ledger_Reader_Writer::mkdir_cross_OS(const char * path)
{
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
	return _mkdir(path);
#else
	return mkdir(path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
#endif
}

/* This function is only used in the client code
 * Will load 2 keys from files:
 * 1. Ledger's public data key (for request data encryption)
 * 2. Ledger's public signing key (for response data signature verification)
 */
bool Ledger_Reader_Writer::load_keys_from_files()
{
	std::string full_name;
	
	// if this is called again, need to free previous keys
	delete_keys();
	
	// try to load the ledger public key	
	if (get_full_file_name(LEDGER_PUBLIC_DATA_KEY_FILENAME, full_name) == false)
	{
		PRINT(ERROR, CRYPTO, "get_full_file_name failed\n");
		return false; // m_keys_initialized remains false
	}

	if (load_public_ec_key_from_file(&m_remote_public_ec_key, full_name.c_str()) == false) 
	{
		PRINT(ERROR, CRYPTO, "load_public_ec_key_from_file failed\n");
		return false; // m_keys_initialized remains false
	}
	
	if (get_full_file_name(LEDGER_PUBLIC_SIGN_KEY_FILENAME, full_name) == false)
	{
		PRINT(ERROR, CRYPTO, "get_full_file_name failed\n");
		return false; // m_keys_initialized remains false
	}

	if (load_public_ec_key_from_file(&m_remote_public_sign_ec_key, full_name.c_str()) == false) 
	{
		PRINT(ERROR, CRYPTO, "load_public_ec_key_from_file failed\n");
		return false; // m_keys_initialized remains false
	}
	
	m_keys_initialized = true;
	
	return true;
}
#endif


bool Ledger_Reader_Writer::set_data_keys(const public_ec_key_str_t* p_local_public_key_str, const private_ec_key_str_t* p_local_private_key_str)
{
	if (p_local_public_key_str == NULL || p_local_private_key_str == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}
	
	if (m_local_ec_key != NULL)
	{
		EC_KEY_free(m_local_ec_key);
		m_local_ec_key = NULL;
	}
		
	if (create_public_ec_key_from_str(&m_local_ec_key, p_local_public_key_str) == false)
	{
		PRINT(ERROR, CRYPTO, "create_public_ec_key_from_str failed\n");
		return false;
	}
	// assert(m_local_ec_key != NULL);
	
	if (add_private_ec_key_from_str(m_local_ec_key, p_local_private_key_str) == false)
	{
		PRINT(ERROR, CRYPTO, "add_private_ec_key_from_str failed\n");
		return false;
	}
	
	m_keys_initialized = true; // data keys are enough for decryption
	
	return true;
}


bool Ledger_Reader_Writer::set_signing_keys(const public_ec_key_str_t* p_local_public_key_str, const private_ec_key_str_t* p_local_private_key_str)
{
	if (p_local_public_key_str == NULL || p_local_private_key_str == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}
	
	if (m_local_sign_ec_key != NULL)
	{
		EC_KEY_free(m_local_sign_ec_key);
		m_local_sign_ec_key = NULL;
	}
		
	if (create_public_ec_key_from_str(&m_local_sign_ec_key, p_local_public_key_str) == false)
	{
		PRINT(ERROR, CRYPTO, "create_public_ec_key_from_str failed\n");
		return false;
	}
	// assert(m_local_sign_ec_key != NULL);
	
	if (add_private_ec_key_from_str(m_local_sign_ec_key, p_local_private_key_str) == false)
	{
		PRINT(ERROR, CRYPTO, "add_private_ec_key_from_str failed\n");
		return false;
	}
	
	if (m_local_ec_key != NULL) // signing keys always also need data keys
		m_keys_initialized = true;
	
	return true;
}

bool Ledger_Reader_Writer::set_signing_public_key(const public_ec_key_str_t* p_local_public_key_str)
{
	if (p_local_public_key_str == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}

	if (m_local_sign_ec_key != NULL)
	{
		EC_KEY_free(m_local_sign_ec_key);
		m_local_sign_ec_key = NULL;
	}

	if (create_public_ec_key_from_str(&m_local_sign_ec_key, p_local_public_key_str) == false)
	{
		PRINT(ERROR, CRYPTO, "create_public_ec_key_from_str failed\n");
		return false;
	}

	if (m_local_ec_key != NULL) // signing keys always also need data keys
		m_keys_initialized = true;

	return true;
}

// should be called with session+public keys (when called by the client creating a txn) or with local+session keys (when called by the enclave to decrypt a txn)
bool Ledger_Reader_Writer::prepare_session_key(EC_KEY* local_or_session_private_ec_key, EC_KEY* session_or_remote_public_ec_key, request_type_e type, uint16_t req_svn, kdf16_key_t* session_aes_key)
{
	bool retval = false;
	kdf_nonce_t kdf_nonce1 = {};
	kdf_nonce_t kdf_nonce2 = {};
	const char* first_derivation_label = NULL;
	const char* second_derivation_label = NULL;
	
	if (m_keys_initialized == false || m_svn_initialized == false)
	{
		PRINT(ERROR, CRYPTO, "keys or svn are not initalized\n");
		return false;
	}
	
	if (session_aes_key == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}
	
	do {
		if (local_or_session_private_ec_key != NULL && session_or_remote_public_ec_key != NULL)
		{
			if (calculate_dh_shared_secret(local_or_session_private_ec_key, session_or_remote_public_ec_key, &m_dh_shared_secret) == false)
			{
				PRINT(ERROR, CRYPTO, "calculate_dh_shared_secret failed\n");
				break;
			}
			m_dh_shared_secret_initialized = true;
		}
		else
		{
			if (m_dh_shared_secret_initialized == false)
			{
				PRINT(ERROR, CRYPTO, "dh_shared_secret is not initialized\n");
				break;
			}
		}
		
		//PRINT(ERROR, CRYPTO, "dh shared secret:\n");
		//print_byte_array(dh_shared_secret, DH_SHARED_SIZE);
				
		if (safe_memcpy(kdf_nonce1, sizeof(kdf_nonce_t), &m_dh_shared_secret, DH_SHARED_SIZE) == false ||
			safe_memcpy(kdf_nonce2, sizeof(kdf_nonce_t), &req_svn, sizeof(uint16_t)) == false)
		{
			PRINT(ERROR, CRYPTO, "safe_memcpy failed\n");
			break;
		}
		
		first_derivation_label = AES_1ST_DERIVATION_LABEL;
		
		if (type == TYPE_READER_REQUEST)
			second_derivation_label = AES_REQUEST_2ND_DERIVATION_LABEL;
		else if (type == TYPE_READER_RESPONSE)
			second_derivation_label = AES_RESULT_2ND_DERIVATION_LABEL;
		else if (type == TYPE_TRANSACTION)
			second_derivation_label = AES_TRANSACTION_2ND_DERIVATION_LABEL;
		else
		{
			PRINT(ERROR, CRYPTO, "resuest type is unknown\n");
			break;
		}
		
		if (derive_16bytes_key_from_double_cmac_aes_128(first_derivation_label, kdf_nonce1, second_derivation_label, kdf_nonce2, session_aes_key) == false)
		{
			PRINT(ERROR, CRYPTO, "derive_16bytes_key_from_double_cmac_aes_128 failed\n");
			break;
		}
				
		retval = true;
		
	} while(0);	
	
	// cleanup
	memset_s(kdf_nonce1, KDF_NONCE_SIZE, 0, KDF_NONCE_SIZE);
	// kdf_nonce2 do not hold a secret
	
	return retval;
}

// encrypt according to ecies scheme
bool Ledger_Reader_Writer::encode_secure_data(const ledger_hex_address_t address, const uint8_t* data, size_t data_size, request_type_e type, char** b64_request_str)
{
	secure_data_content_t* p_request_data = NULL; // this will be encryted into the payload inside the request
	secure_data_t* p_request = NULL;
	EC_KEY* session_ec_key = NULL;
	kdf16_key_t session_aes_key = {0};
	public_ec_key_str_t remote_public_key_str = {0};
	bool retval = false;
		
	if (b64_request_str == NULL || (data != NULL && data_size == 0))
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}
	
	if (data_size > MAX_CRYPTO_BUFFER_SIZE)
	{
		PRINT(ERROR, CRYPTO, "buffer size is too big\n");
		return false;
	}
	
	if (m_keys_initialized == false || m_svn_initialized == false)
	{
		PRINT(ERROR, CRYPTO, "keys or svn are not initialized\n");
		return false;
	}
	
	for (size_t i = 0 ; i < sizeof(ledger_hex_address_t)-1 ; i++)
	{
		if (OPENSSL_hexchar2int(address[i]) == -1)
		{
			PRINT(ERROR, CRYPTO, "address contains non-hex characters\n");
			return false;
		}
	}
	if (address[sizeof(ledger_hex_address_t)-1] != '\0')
	{
		PRINT(ERROR, CRYPTO, "address is not NULL terminated\n");
		return false;
	}
		
	do {
		
		p_request_data = (secure_data_content_t*)malloc(sizeof(secure_data_content_t) + data_size);
		if (p_request_data == NULL)
		{
			PRINT(ERROR, CRYPTO, "malloc failed\n");
			break;
		}
		memset_s(p_request_data, sizeof(secure_data_content_t) + data_size, 0, sizeof(secure_data_content_t) + data_size);
		
		p_request = (secure_data_t*)malloc(sizeof(secure_data_t) + data_size);
		if (p_request == NULL)
		{
			PRINT(ERROR, CRYPTO, "malloc failed\n");
			break;
		}
		memset_s(p_request, sizeof(secure_data_t) + data_size, 0, sizeof(secure_data_t) + data_size);
		
		// prepare the request_data
		if (safe_memcpy(p_request_data->address, sizeof(ledger_hex_address_t), address, sizeof(ledger_hex_address_t)) == false)
		{
			PRINT(ERROR, CRYPTO, "safe_memcpy failed\n");
			break;
		}
		
		if (data_size != 0)
		{
			if (safe_memcpy(p_request_data->data, data_size, data, data_size) == false)
			{
				PRINT(ERROR, CRYPTO, "safe_memcpy failed\n");
				break;
			}
			p_request->secure_data_payload.size = data_size;
		}
		
		if (type == TYPE_READER_REQUEST || type == TYPE_TRANSACTION)
		{
			if (get_random_bytes((unsigned char*)&p_request_data->nonce, sizeof(uint64_t)) == false)
			{
				PRINT(ERROR, CRYPTO, "can't get random bytes\n");
				break;
			}
			
			m_nonce = p_request_data->nonce; // for request, save it and check with the response, prevent reply attack
			
			// response uses the same session key as the request
			if (create_new_ec_key_pair(&session_ec_key) == false)
			{
				PRINT(ERROR, CRYPTO, "create_new_ec_key_pair failed\n");
				break;
			}
			
			// add the session's public key
			if (get_ec_public_key_as_str(session_ec_key, &p_request->secure_data_payload.session_pub_str) == false)
			{
				PRINT(ERROR, CRYPTO, "get_ec_public_key_as_str failed\n");
				break;
			}
			
			// add the hash of the remote key, so it can be checked to avoid confusions (using the wrong key to create the DH)
			if (get_ec_public_key_as_str(m_remote_public_ec_key, &remote_public_key_str) == false)
			{
				PRINT(ERROR, CRYPTO, "get_ec_public_key_as_str failed\n");
				break;
			}
			
			if (sha256_msg((const uint8_t*)&remote_public_key_str, sizeof(public_ec_key_str_t), &p_request->secure_data_payload.ledger_pub_hash) == false)
			{
				PRINT(ERROR, CRYPTO, "sha256_msg failed\n");
				break;
			}
		}
		else
		{
			assert(type == TYPE_READER_RESPONSE);
			p_request_data->nonce = m_nonce; // copy the original request nonce
		}
				
		// when encoding, using the current svn
		if (prepare_session_key(session_ec_key, m_remote_public_ec_key, type, m_svn, &session_aes_key) == false)
		{
			PRINT(ERROR, CRYPTO, "prepare_session_key failed\n");
			break;
		}
		
		// encrypt the request data
		if (aes_encrypt((uint8_t*)p_request_data, (uint32_t)sizeof(secure_data_content_t) + data_size, 
						session_aes_key, AES_KEY_SIZE, // aes key is the shared pre-calculated key
						p_request->secure_data_payload.iv, AES_IV_SIZE, // iv is randomized inside
						(uint8_t*)&p_request->secure_data_payload.encrypted_data_content, (uint32_t)sizeof(secure_data_content_t) + data_size,
						p_request->secure_data_payload.mac, AES_MAC_SIZE) == false)
		{
			PRINT(ERROR, CRYPTO, "aes_encrypt failed\n");
			break;
		}
		
		// add the public key to identify the signer
		if (get_ec_public_key_as_str(m_local_sign_ec_key, &p_request->header.pub_key_str) == false)
		{
			PRINT(ERROR, CRYPTO, "get_ec_public_key_as_str failed\n");
			break;
		}
		
		p_request->secure_data_payload.ledger_svn = m_svn;
			
		if (sha512_msg((const uint8_t*)&p_request->secure_data_payload, (uint32_t)sizeof(secure_data_payload_t) + data_size, &p_request->header.payload_hash) == false)
		{
			PRINT(ERROR, CRYPTO, "sha512_msg failed\n");
			break;
		}
		
		//PRINT(INFO, CRYPTO, "sha512 of payload:\n");
		//print_byte_array(p_request.payload_hash, sizeof(sha512_data_t));
		
		p_request->header.magic = SECURE_DATA_MAGIC;
		p_request->header.type = type;
		p_request->header.version = TXN_SW_VERSION;

		if (type != TYPE_TRANSACTION) // don't need to sign txn payload, whole transaction is signed
		{
#if defined(SKIP_SIGN) && !defined(SGX_ENCLAVE) // outside of enclave and skip signature
			PRINT(INFO, CRYPTO, "skipping signature\n");
#elif defined(HSM_SIGN) && !defined(SGX_ENCLAVE)// outside the enclave and use hsm sign
			// sign the header
			if (hsm_sign((uint8_t*)&p_request->header, sizeof(secure_data_header_t), p_request->header.pub_key_str, (uint8_t*)&p_request->sig) == false)
			{
				PRINT(ERROR, CRYPTO, "hsm_sign failed\n");
				break;
			}

			// hsm_sign is external code, verify that indeed they put a valid signature
			if (ecdsa_verify((uint8_t*)&p_request->header, sizeof(secure_data_header_t), m_local_sign_ec_key, &p_request->sig) == false)
			{
				PRINT(ERROR, CRYPTO, "hsm_sign signature failed to be verified\n");
				break;
			}
#else // in enclave or no signature alternatives
			// sign the header
			if (ecdsa_sign((uint8_t*)&p_request->header, sizeof(secure_data_header_t), m_local_sign_ec_key, &p_request->sig) == false)
			{
				PRINT(ERROR, CRYPTO, "ecdsa_sign failed\n");
				break;
			}
#endif
		}// end of: if (type != TYPE_TRANSACTION)

		// from OpenSSL documentations:
		// EVP_EncodeBlock() encodes a full block of input data in f and of length dlen and stores it in t. For every 3 bytes of input provided 4 bytes of output data will be produced.
		*b64_request_str = (char*)malloc((sizeof(secure_data_t) + data_size) *2);
		if (*b64_request_str == NULL)
		{
			PRINT(ERROR, CRYPTO, "malloc failed\n");
			break;
		}
		
		// base64 string
		uint32_t str_len = EVP_EncodeBlock((unsigned char*)*b64_request_str, (uint8_t*)p_request, (int)(sizeof(secure_data_t) + data_size));
		if (str_len == 0 || str_len > (sizeof(secure_data_t) + data_size)*2)
		{
			PRINT(ERROR, CRYPTO, "EVP_EncodeBlock failed\n");
			break;
		}
		
		retval = true;
	
	} while(0);
	
	// cleanup
	if (p_request != NULL)
		free(p_request);
		
	if (p_request_data != NULL)
	{
		memset_s(p_request_data, sizeof(secure_data_content_t) + data_size, 0, sizeof(secure_data_content_t) + data_size);
		free(p_request_data);
	}
	
	if (retval == false && *b64_request_str != NULL)
	{
		free(*b64_request_str);
		*b64_request_str = NULL;
	}
	
	if (session_ec_key != NULL)
		EC_KEY_free(session_ec_key);
		
	memset_s(session_aes_key, sizeof(kdf16_key_t), 0, sizeof(kdf16_key_t));
	
	return retval;
}


bool Ledger_Reader_Writer::get_secure_data_svn(const char* b64_secure_data_str, uint16_t* svn)
{
	uint8_t secure_data_arr[sizeof(secure_data_t) + 10] = {}; // the decoding can be 2 bytes longer depending on alignment of the structure, 
	secure_data_t* secure_data = (secure_data_t*)secure_data_arr;
	uint64_t magic = 0;

	if (b64_secure_data_str == NULL || svn == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}

	int required_string_len = (sizeof(secure_data_t) * 4) / 3;
	// EVP_DecodeBlock works on strings that have to be multiply of 4, the full string should be correct since it is the output of EVP_EncodeBlock,
	// but since we only use part of it, we need to align the requested size. this may result in a longer output which is why we have the padding above
	if ((required_string_len % 4) != 0)
		required_string_len += (4 - (required_string_len % 4));

	if ((int)strnlen(b64_secure_data_str, MAX_NETWORK_MSG_SIZE) < required_string_len)
	{
		PRINT(ERROR, CRYPTO, "input string is too short\n");
		return false;
	}

	int decode_size = EVP_DecodeBlock(secure_data_arr, (unsigned char *)b64_secure_data_str, required_string_len);
	if (decode_size < (int)sizeof(secure_data_t))
	{
		PRINT(ERROR, CRYPTO, "EVP_DecodeBlock failed, returned %d bytes, expected at least %ld bytes\n", decode_size, sizeof(secure_data_t));
		return false;
	}

	magic = secure_data->header.magic;
	if (magic != SECURE_DATA_MAGIC)
	{
		PRINT(ERROR, CRYPTO, "EVP_DecodeBlock result is incorrect (bad magic)\n");
		return false;
	}

	*svn = secure_data->secure_data_payload.ledger_svn;
	return true;
}


// decrypt according to ecies scheme
// todo - change parameters names - remove request/response...
bool Ledger_Reader_Writer::decode_secure_data(const char* b64_request_str, secure_data_content_t** pp_output_data, size_t* output_size, public_ec_key_str_t* p_remote_pub_key_str)
{
	secure_data_t* p_request = NULL;
	secure_data_content_t* p_request_data = NULL;
    sha512_data_t payload_hash = {0};
	kdf16_key_t session_aes_key = {0};
	EC_KEY* session_ec_key = NULL;	
	size_t decrypt_size = 0;
    bool retval = false;
#ifdef SGX_ENCLAVE
	public_ec_key_str_t ledger_pub_str = {0};
	sha256_data_t ledger_pub_hash = {0};
#endif

    
	if (b64_request_str == NULL || pp_output_data == NULL || output_size == NULL)
	{
		PRINT(ERROR, CRYPTO, "wrong input parameters\n");
		return false;
	}
	
	if (m_keys_initialized == false || m_svn_initialized == false)
	{
		PRINT(ERROR, CRYPTO, "keys or svn are not initialized\n");
		return false;
	}
	
	if (strnlen(b64_request_str, MAX_NETWORK_MSG_SIZE) > MAX_NETWORK_MSG_SIZE-1)
	{
		PRINT(ERROR, CRYPTO, "request string size is too big\n");
		return false;
	}
	
	do {
	
		uint32_t max_request_size = (uint32_t)strnlen(b64_request_str, MAX_NETWORK_MSG_SIZE);
		
		p_request = (secure_data_t*)malloc(max_request_size);
		if (p_request == NULL)
		{
			PRINT(ERROR, CRYPTO, "malloc failed\n");
			break;
		}
		memset_s(p_request, max_request_size, 0, max_request_size);
		
		int decode_size = EVP_DecodeBlock((uint8_t*)p_request, (unsigned char*)b64_request_str, max_request_size);
		if (decode_size < (int)sizeof(secure_data_t))
		{
			PRINT(ERROR, CRYPTO, "EVP_DecodeBlock failed, returned %d bytes, expected at least %ld bytes\n", decode_size, sizeof(secure_data_t));
			break;
		}
		
		// verify the decoding went well and the magic number is in place
		if (p_request->header.magic != SECURE_DATA_MAGIC)
		{
			PRINT(ERROR, CRYPTO, "EVP_DecodeBlock result is incorrect (bad magic)\n");
			break;
		}
		
		if (p_request->header.version != TXN_SW_VERSION)
		{
			PRINT(ERROR, CRYPTO, "unsupported transaction or request version\n");
			break;
		}
		
		if (p_request->secure_data_payload.size > MAX_CRYPTO_BUFFER_SIZE)
		{
			PRINT(ERROR, CRYPTO, "buffer size is too big\n");
			break;
		}
		// decode size will be padded with 0 so for every 4 bytes of input exacly 3 bytes will be produced
		auto expected_size = sizeof(secure_data_t) + p_request->secure_data_payload.size;
		expected_size = ((expected_size+2)/3)*3;// round up to nearest multiple of 3
		if ((unsigned int)decode_size != expected_size)
		{
			PRINT(ERROR, CRYPTO, "EVP_DecodeBlock failed, returned %d bytes, expected %ld bytes\n",
								 decode_size, expected_size);
			break;
		}

#ifdef SGX_ENCLAVE
		// check that the SVN in the request or transaction is correct
		if (p_request->header.type == TYPE_READER_REQUEST)
		{
			if (p_request->secure_data_payload.ledger_svn != m_svn)
			{
				PRINT(ERROR, CRYPTO, "request svn (0x%x) is different from the ledger svn (0x%x)\n", p_request->secure_data_payload.ledger_svn, m_svn);
				break;
			}
			
			// todo - consider saving this hash somewhere, instead of calculating it every time
			if (get_ec_public_key_as_str(m_local_ec_key, &ledger_pub_str) == false)
			{
				PRINT(ERROR, CRYPTO, "get_ec_public_key_as_str failed\n");
				return false;
			}
			
			if (sha256_msg((const uint8_t*)&ledger_pub_str, sizeof(public_ec_key_str_t), &ledger_pub_hash) == false)
			{
				PRINT(ERROR, CRYPTO, "sha256_msg failed\n");
				return false;
			}
			
			if (memcmp(p_request->secure_data_payload.ledger_pub_hash, ledger_pub_hash, sizeof(sha256_data_t)) != 0)
			{
				PRINT(ERROR, CRYPTO, "secure data is encrypted with a wrong ledger public key, data can't be decrypted\n");
				return false;
			}

			// verify client's public key is in the DB and have permission, to reduce DoS impact
			//TODO remove conversion when we have one type of key
			// convert c array to std array
			SignerPubKey pub_key_str_arr;

			// copy and convert to lower case
			for (uint32_t i = 0 ; i < sizeof(public_ec_key_str_t) ; i++)
			{
				pub_key_str_arr[i] = (char)tolower(p_request->header.pub_key_str[i]);
			}


			if (acl::acl_is_member(pub_key_str_arr) == false)
			{
				PRINT(ERROR, CRYPTO, "client's public key is unknown\n");
				break;
			}

			//copying the lower case version since Sawtooth keys are represented as lower case
			if (safe_memcpy(p_remote_pub_key_str, sizeof(public_ec_key_str_t), pub_key_str_arr.data(), sizeof(public_ec_key_str_t)) == false)
			{
				PRINT(ERROR, CRYPTO, "safe_memcpy failed\n");
				break;
			}
		}
		
		if (p_request->header.type == TYPE_TRANSACTION)
		{
			if (p_request->secure_data_payload.ledger_svn > m_svn) // this could be an attack, trying to process new data on an older less secure enclave (smaller svn is ok)
			{
				PRINT(ERROR, CRYPTO, "request svn (0x%x) is bigger than ledger svn (0x%x)\n", p_request->secure_data_payload.ledger_svn, m_svn);
				break;
			}
		}
		// on the server side the remote public key - client's key, comes from the request
		assert(m_remote_public_sign_ec_key == NULL);
		if (create_public_ec_key_from_str(&m_remote_public_sign_ec_key, &p_request->header.pub_key_str) == false)
		{
			PRINT(ERROR, CRYPTO, "create_public_ec_key_from_str failed\n");
			return false;
		}
		assert(m_remote_public_sign_ec_key != NULL);
#else
		(void)p_remote_pub_key_str; // remove unused warning
#endif // SGX_ENCLAVE

		if (sha512_msg((const uint8_t*)&p_request->secure_data_payload, (uint32_t)sizeof(secure_data_payload_t) + p_request->secure_data_payload.size, &payload_hash) == false)
		{
			PRINT(ERROR, CRYPTO, "sha512_msg failed\n");
			break;
		}
		
		// no need for const time memcmp, only comparing hash here, attacker can't learn anything from timing here
		if (memcmp(payload_hash, p_request->header.payload_hash, sizeof(sha512_data_t)) != 0)
		{
			PRINT(ERROR, CRYPTO, "request hash is incorrect\n");
			break;
		}
		if (p_request->header.type != TYPE_TRANSACTION) // decrypting txn paylod, signature is checked for full transaction
		{
			if (ecdsa_verify((const uint8_t*)&p_request->header, sizeof(secure_data_header_t), m_remote_public_sign_ec_key, &p_request->sig) == false)
			{
				PRINT(ERROR, CRYPTO, "ecdsa_verify failed\n");
				break;
			}
		}
		
		if (p_request->header.type != TYPE_READER_RESPONSE) // decrypting response, must be client side, we should already have the dh_shared_secret
		{
			if (create_public_ec_key_from_str(&session_ec_key, &p_request->secure_data_payload.session_pub_str) == false)
			{
				PRINT(ERROR, CRYPTO, "create_public_ec_key_from_str failed\n");
				break;
			}
		}
		
		// use the original svn from the request, the keys should also match that svn
		if (prepare_session_key(m_local_ec_key, session_ec_key, p_request->header.type, p_request->secure_data_payload.ledger_svn, &session_aes_key) == false)
		{
			PRINT(ERROR, CRYPTO, "prepare_session_key failed\n");
			break;
		}
		
		decrypt_size = sizeof(secure_data_content_t) + p_request->secure_data_payload.size;
		p_request_data = (secure_data_content_t*)malloc(decrypt_size);
		if (p_request_data == NULL)
		{
			PRINT(ERROR, CRYPTO, "malloc failed\n");
			break;
		}

		if (aes_decrypt((uint8_t*)&p_request->secure_data_payload.encrypted_data_content, decrypt_size,
						p_request->secure_data_payload.iv, AES_IV_SIZE,
						p_request->secure_data_payload.mac, AES_MAC_SIZE,
						session_aes_key, AES_KEY_SIZE,
						(uint8_t*)p_request_data, decrypt_size) == false)
		{
			PRINT(ERROR, CRYPTO, "aes_decrypt failed\n");
			break;
		}
		
		if (p_request->header.type == TYPE_READER_RESPONSE)
		{
			if (p_request_data->nonce != m_nonce)
			{
				PRINT(ERROR, CRYPTO, "request nonce mismatch\n");
				break;
			}
		}
		else
		{
			m_nonce = p_request_data->nonce; // for request, to be copied into the response
		}
		
		*pp_output_data = p_request_data;
		*output_size = decrypt_size;
		
		retval = true;
		
	} while (0);
	
	// cleanup
	memset_s(session_aes_key, sizeof(kdf16_key_t), 0, sizeof(kdf16_key_t));
		
	if (p_request != NULL)
		free(p_request);
		
	if (session_ec_key != NULL)
		EC_KEY_free(session_ec_key);
	
	if (retval == false && p_request_data != NULL)
	{
		memset_s(p_request_data, decrypt_size, 0, decrypt_size);
		free(p_request_data);
	}
	
	return retval;
}

