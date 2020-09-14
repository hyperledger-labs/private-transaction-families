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
 
#ifndef _LEDGER_KEYS_H_
#define _LEDGER_KEYS_H_

#include <sgx_tcrypto.h>
#include <sgx_quote.h>
#include <sgx_spinlock.h>
#include "crypto.h"

#define LEDGER_ADD_STRING "Sawtooth Ledger Keys"
#define LEDGER_ADD_STRING_LEN 20 // without trailing \0

#define MAX_IAS_KEY_LEN 34 // TODO:  This is not specifically noted in documentation
#define SPID_BLOB_SIZE (sizeof(sgx_spid_t)*2+1)

typedef struct _ledger_base_keys_t
{
	uint16_t version;
	
// ec a-symmetric keys used by the server sync module
// uses sgx-sdk remote attestation protocol, little endian keys, ec with nist256p1 params
	sgx_ec256_public_t	ra_pub_ec_key; // used by client to encrypt the data (g_a), g is defined by the curve - nist256p1
	sgx_ec256_private_t	ra_priv_ec_key; // used by the enclave to decrypt the data (a)
	
// save the SVN so we can check it's match when we load the file
	uint16_t ledger_svn;
	
// key derivation secret - the root for all the ledger keys
	kdf32_key_t kds;
	ecdsa_bin_signature_t kds_signature; // signature of the kds, signed by admin key
	
// reserved space for future need
	uint64_t reserved[32];
	
// these are for IAS communication, SPID, private certificate and private key
	sgx_spid_t ias_spid;
	uint8_t ias_key_str[MAX_IAS_KEY_LEN];

} ledger_base_keys_t;


// the key in this structure is derived from the kds!
typedef struct _ledger_keys_t
{
// these are ec a-symmetric keys, uses openssl and sawtooth protocol, big endian keys, ec secp256k1 params
	public_ec_key_str_t data_pub_ec_key_str;
	private_ec_key_str_t data_priv_ec_key_str;
} ledger_keys_t;


class Ledger_Keys_Manager
{
private:
	sgx_spinlock_t lock; // todo - change to mutex
	ledger_base_keys_t ledger_base_keys; // loaded and unsealed from file 
	
	kdf32_key_t* kds_array; // generated from the kds in the base keys
	ledger_keys_t* ledger_keys_array; // generated from the matching kds
	
	// sign keys are only used for responses of read requests, only current svn is used
	public_ec_key_str_t sign_pub_ec_key_str;
	private_ec_key_str_t sign_priv_ec_key_str;
	
	bool keys_initialized;
	
	bool load_ledger_base_keys();
	bool initialize_keys();
	void internal_cleanup();
	
public:
	Ledger_Keys_Manager();
	~Ledger_Keys_Manager();
		
	// this function should be called if we don't want to test for NULL in the get_* functions
	bool keys_ready();
	
	uint16_t get_svn();
		
	const ledger_base_keys_t* get_ledger_base_keys();
	
	const ledger_keys_t* get_current_ledger_keys();
	const ledger_keys_t* get_ledger_keys_by_svn(uint16_t svn);
	
	const kdf32_key_t* get_current_kds();
	const kdf32_key_t* get_kds_by_svn(uint16_t svn);
	
	const public_ec_key_str_t* get_public_signing_key();
	const private_ec_key_str_t* get_private_signing_key();
};

// single global instance
extern Ledger_Keys_Manager ledger_keys_manager;

#endif // _LEDGER_KEYS_H_
