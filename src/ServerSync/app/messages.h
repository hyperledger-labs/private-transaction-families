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

#ifndef _MESSAGES_H_
#define _MESSAGES_H_

#include <sgx_ukey_exchange.h>
#include <sgx_uae_service.h>

#include "ledger_keys.h"

#include "client_network.h"

// server side functions
int server_proc_msg1(uint32_t ias_socket,
					 uint64_t* p_session_id,
					 const sgx_ra_msg1_t* p_ra_msg1, size_t msg1_size,
					 char** pp_msg2, size_t* p_msg2_size);
					 
int server_proc_msg3(uint64_t session_id,
					 const sgx_ra_msg3_t* p_msg3, size_t msg3_size,
                     char** pp_msg4, size_t* p_msg4_size);
                     
void server_proc_cleanup(uint64_t session_id);

#endif // _MESSAGES_H_
