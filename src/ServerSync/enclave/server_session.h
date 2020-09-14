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
 
#include <sgx_key_exchange.h>
#include <sgx_tcrypto.h>
#include <sgx_quote.h>

#include "ias_session.h"

// session data
typedef struct _session_t
{
    sgx_ec256_public_t		g_a;    // client's public ec (asymetric) key
    sgx_ec256_public_t		g_b;    // server's public ec (asymetric) key
    sgx_ec256_private_t		b;      // server's private ec (asymetric) key
    
    sgx_key_128bit_t		vk_key; // shared secret key for the REPORT_DATA (a hash) in msg3
    sgx_key_128bit_t		sk_key; // shared secret key for encryption of the ledger keys in msg4
    sgx_key_128bit_t		smk_key;// shared secret key for CMAC of msg2 and msg3 content
      
    // these are saved since msg1 handling is split - in the first phase, we get the sig_rl from the ias and return the size to the untrusted for buffer allocation
    // the sig_rl is only copied in the second phase. we also make sure the gid remains the same.
    sgx_epid_group_id_t		gid;
    uint8_t*				sig_rl; 
    size_t					sig_rl_size;
 
    ias_session_t*			p_ias_session;
}session_t;


#ifdef  __cplusplus
extern "C" {
#endif
uint64_t add_session(session_t* session);
session_t* get_session(uint64_t session_id);
void free_session(uint64_t session_id);
#ifdef  __cplusplus
}
#endif
