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
 
#ifndef _CRYPTO_LEDGER_READER_WRITER_H_
#define _CRYPTO_LEDGER_READER_WRITER_H_

#include <stdint.h>
#include <string>
#include "crypto.h"
#include "crypto_transaction.h"


class Ledger_Reader_Writer
{
private:
	
	EC_KEY* m_local_ec_key; // public and private key
	EC_KEY* m_local_sign_ec_key; // public and private key
	
	EC_KEY* m_remote_public_ec_key; // only public key
	EC_KEY* m_remote_public_sign_ec_key; // only public key
	
	bool m_keys_initialized;
	bool m_svn_initialized;
	
	uint16_t m_svn; // the current ledger svn level
	uint64_t m_nonce; // required for client reader
	
	dh_shared_secret_t m_dh_shared_secret;
	bool m_dh_shared_secret_initialized;

	void delete_keys();
	bool prepare_session_key(EC_KEY* local_or_session_private_ec_key, EC_KEY* session_or_remote_public_ec_key, request_type_e type, uint16_t req_svn, kdf16_key_t* session_aes_key);
	int mkdir_cross_OS(const char * path);

#ifndef SGX_ENCLAVE
	std::string m_path; // if this remains empty, the default keys path is "HOME"/KEYS_DIR_NAME (e.g. /home/user1/.stl_keys)
	
	bool get_full_file_name(const char* filename, std::string& full_name);
#endif
	
public:
	Ledger_Reader_Writer();
	Ledger_Reader_Writer(uint64_t nonce, dh_shared_secret_t* dh_shared_secret);
	~Ledger_Reader_Writer();
	
	void set_svn(uint16_t ledger_svn);

#ifndef SGX_ENCLAVE
	void set_files_path(const char* path_name); // if this is not called, the default keys path is "HOME"/KEYS_DIR_NAME (e.g. /home/user1/.stl_keys)
	// used by client app code
	bool load_keys_from_files();
#endif

	// used by client reader enclave code
	bool set_data_keys(const public_ec_key_str_t* p_local_public_key_str, const private_ec_key_str_t* p_local_private_key_str);
	bool set_signing_keys(const public_ec_key_str_t* p_local_public_key_str, const private_ec_key_str_t* p_local_private_key_str);
	bool set_signing_public_key(const public_ec_key_str_t* p_local_public_key_str);

	// this function is used by the client reader app to create a read request, by the ledger app for creating transactions, and by the enclave to create response for read requests
	// for client reader data should be NULL and data_size should be 0
	// outputs a b64 encoded string
	// output should be freed by the caller
	bool encode_secure_data(const ledger_hex_address_t address, const uint8_t* data, size_t data_size, request_type_e type, char** b64_request_str);
	
	// this function is used by the transaction processor to extract the svn before starting to decode, so it can set the right keys
	bool get_secure_data_svn(const char* b64_secure_data_str, uint16_t* svn);
	
	// this function is used by the client reader to decrypt the response, and by the enclave to decrypt read requests and transactions
	// input is a b64 encoded string, created by encode_secure_data
	// output should be freed by the caller
	bool decode_secure_data(const char* b64_response_str, secure_data_content_t** output_response, size_t* output_size, public_ec_key_str_t* p_remote_pub_key_str);

	uint64_t get_nonce();
	bool get_dh_shared_secret(dh_shared_secret_t* dh_shared_secret);
};

#endif // _CRYPTO_LEDGER_READER_WRITER_H_
