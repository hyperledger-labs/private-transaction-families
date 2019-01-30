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

#ifndef _CRYPTO_TRANSACTION_H_
#define _CRYPTO_TRANSACTION_H_

#include "crypto.h"

typedef enum {
	TYPE_READER_REQUEST,
	TYPE_READER_RESPONSE,
	TYPE_TRANSACTION,
} request_type_e;

// magic is only used to verify that the 'base64 encode->network->base64 decode' went well
#define SECURE_DATA_MAGIC 0xabcd4567

#pragma pack(1)

typedef struct __secure_data_content_t
{
	// client reader verifies the response nonce is identical to the request nonce
    uint64_t nonce;
    
    // this is a hex string, all of it must be used, so the last byte must be '\0', only hex characters allowed (0-9, a-f, A-F)
    ledger_hex_address_t address;
    
    // for transactions and client reader response, not used in client reader requests
    uint8_t data[];
} secure_data_content_t;

// todo - add the remote side public key (the target, the one used with the local session key to generate the common secret) used for the encryption, so it can be checked

typedef struct __secure_data_payload_t
{
	// temporary random key used only for this request encryption (extracting aes key from dh shared secret), ecies scheme
    public_ec_key_str_t session_pub_str;
    // hash of the target public key that was used for creating the shared secret
    sha256_data_t ledger_pub_hash;
    // the svn used when preparing the session key (also implies what was the public ledger key)
    uint16_t ledger_svn;
    
	// encryption data
    uint8_t iv[AES_IV_SIZE];
    uint8_t mac[AES_MAC_SIZE];
    
    // size of the data following this structure, should be 0 for client reader
    uint64_t size;
    
    secure_data_content_t encrypted_data_content;
} secure_data_payload_t;


typedef struct __secure_data_header_t
{
	// used for initial verification of the buffer
	uint64_t magic;
	
	uint16_t version;
	
	// public key for identification
    public_ec_key_str_t pub_key_str;
    
    request_type_e type; // session key is derived according to this value, so if it will be changed the decrypt will fail
    
    // hash of the payload
    sha512_data_t payload_hash;
    
} secure_data_header_t;


typedef struct __secure_data_t
{
	/* HEADER */
	secure_data_header_t header;
    
    /* SIGNATURE */
    // signature of the header with the client's ec private key
    ecdsa_bin_signature_t sig;
      
    /* PAYLOAD */
    secure_data_payload_t secure_data_payload;
} secure_data_t;

#pragma pack()

#endif // _CRYPTO_TRANSACTION_H_
