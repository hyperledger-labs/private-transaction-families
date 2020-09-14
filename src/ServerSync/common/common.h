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
 
#ifndef _COMMON_H_
#define _COMMON_H_

#include "ledger_keys.h"

#include <sgx_uae_epid.h>

// #define VERIFY_PSE_ATTESTATION 1

#define KDS_FILE	 		"genesis_files/kds.hexstr"
#define KDS_SIG_FILE 		"genesis_files/kds_signature.hexstr"

#define IAS_HOST_ADDRESS 	"api.trustedservices.intel.com" // production test server

#ifdef DEBUG

#define IAS_BASE_URL        "/sgx/dev"
#define CERT_FILE 			"genesis_files/ias-test-as.crt"
#define CERT_KEY_FILE 		"genesis_files/ias-test-as.key"
#define SPID_FILE	 		"genesis_files/ias-test-as.spid"

#else // PRODUCTION

#define IAS_BASE_URL        "/sgx"
#define CERT_FILE			"genesis_files/ias-as.crt"
#define CERT_KEY_FILE		"genesis_files/ias-as.key"
#define SPID_FILE	 		"genesis_files/ias-as.spid"

#endif

#define IAS_HOST_PORT_STR 	"443"
#define IAS_HOST_PORT 		443

typedef enum {
    RA_OK = 0,
    RA_UNSUPPORTED_EXTENDED_EPID_GROUP,
    RA_INTEGRITY_FAILED,
    RA_QUOTE_VERIFICATION_FAILED,
    RA_IAS_FAILED,
    RA_INTERNAL_ERROR,
    RA_PROTOCOL_ERROR,
    RA_QUOTE_VERSION_ERROR,
    RA_NO_KEYS,
    RA_MR_ENCLAVE,
    RA_MR_SIGNER,
    RA_ISV_SVN,
    RA_ISV_PROD_ID,
    RA_ENCLAVE_FLAGS,
} ra_status_t;


typedef enum {
    MSG4_OK = 0,
    MSG4_IAS_QUOTE, // enclave quote is not ok
    MSG4_IAS_PSE, // pse manifest is not ok
} msg4_status_t;


typedef struct __sgx_ra_msg4_t
{
	msg4_status_t status;
	union {
		struct { // valid when status == MSG4_OK
			ledger_base_keys_t ledger_keys_blob; // encrypted keys, defined in ledger_keys.h
			sgx_aes_gcm_128bit_tag_t aes_gcm_mac;
		};
		struct { // valid when status != MSG4_OK, only if IAS returned it (which happens only for some error types)
			uint8_t platform_info_valid;
			sgx_platform_info_t platform_info;
		};
	};
} sgx_ra_msg4_t;

#endif // _COMMON_H_
