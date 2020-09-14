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

#ifndef _IAS_SESSION_H
#define _IAS_SESSION_H

#include <openssl/ssl.h>
#include <sgx_quote.h>
#include <sgx_key_exchange.h>

#include "ias.h"

typedef struct _ias_session_t
{
    uint32_t socket;
    SSL_CTX* ctx;
	SSL*     ssl;
} ias_session_t;

ias_session_t* ias_create_session(uint32_t ias_socket);
bool ias_get_sigrl(ias_session_t* p_ias_session, const sgx_epid_group_id_t gid, size_t* p_sig_rl_size, uint8_t** p_sig_rl);
bool ias_verify_attestation_evidence(ias_session_t* p_ias_session, const sgx_quote_t* p_quote, size_t quote_size, const sgx_ps_sec_prop_desc_t* p_ps_sec_prop, ias_att_report_t* p_ias_report);
void ias_destroy_session(ias_session_t* p_ias_session);

#endif // _IAS_SESSION_H
