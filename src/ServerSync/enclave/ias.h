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

#ifndef _IAS_H_
#define _IAS_H_

#include <stdint.h>
#include <sgx_quote.h>
#include "common.h"

typedef enum {
    IAS_QUOTE_OK = 0,
    IAS_QUOTE_SIGNATURE_INVALID,
    IAS_QUOTE_GROUP_REVOKED,
    IAS_QUOTE_SIGNATURE_REVOKED,
    IAS_QUOTE_KEY_REVOKED,
    IAS_QUOTE_SIGRL_VERSION_MISMATCH,
    IAS_QUOTE_GROUP_OUT_OF_DATE,
} ias_quote_status_t;

extern const char* quote_status_strings[];

// These status should align with the definition in IAS API spec(rev 0.6)
typedef enum {
    IAS_PSE_OK = 0,
    IAS_PSE_UNKNOWN,
    IAS_PSE_INVALID,
    IAS_PSE_OUT_OF_DATE,
    IAS_PSE_REVOKED,
    IAS_PSE_RL_VERSION_MISMATCH,
} ias_pse_status_t;

extern const char* pse_status_strings[];

// Revocation Reasons from RFC5280, https://www.ietf.org/rfc/rfc5280.txt, page 69
typedef enum {
    IAS_REVOC_REASON_NONE = 0,
    IAS_REVOC_REASON_KEY_COMPROMISE,
    IAS_REVOC_REASON_CA_COMPROMISED,
    IAS_REVOC_REASON_AFFILIATION_CHANGED,
    IAS_REVOC_REASON_SUPERCEDED,
    IAS_REVOC_REASON_CESSATION_OF_OPERATION,
    IAS_REVOC_REASON_CERTIFICATE_HOLD,
    IAS_REVOC_REASON_NOT_USED,
    IAS_REVOC_REASON_REMOVE_FROM_CRL,
    IAS_REVOC_REASON_PRIVILEGE_WITHDRAWN,
    IAS_REVOC_REASON_AA_COMPROMISE,
} ias_revoc_reason_t;


#define IAS_NONCE_SIZE 16 // this size is not fixed in the protocol

#define IAS_PIB_TYPE 	21 // static value from the IAS spec
#define IAS_PIB_VERSION 2  // static value from the IAS spec

#pragma pack(1)

typedef struct _ias_platform_info_t
{
	uint8_t	type;
	uint8_t	version;
	uint8_t	size_1; // separated so we can convert size from BE to LE
	uint8_t	size_2; // separated so we can convert size from BE to LE
	sgx_platform_info_t platform_info;
} ias_platform_info_t;


typedef struct _ias_att_report_t
{
    uint32_t            revocation_reason; // only used if status == GROUP_REVOKED
    ias_quote_status_t  status;
    uint8_t				platform_info_valid;
    sgx_platform_info_t	platform_info; // only used if status != IAS_QUOTE_OK _or_ pse_status != IAS_PSE_OK _and_ the platform info was returned from the IAS
#ifdef VERIFY_PSE_ATTESTATION
    ias_pse_status_t    pse_status;
#endif
} ias_att_report_t;

#pragma pack()

#endif // _IAS_H_
