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
 
 #ifndef _ENCLAVE_ROLE_H_
#define _ENCLAVE_ROLE_H_

typedef enum {
	ROLE_NONE = 0,
    ROLE_KEYS_GENESIS,
    ROLE_KEYS_SERVER,
    ROLE_KEYS_CLIENT,
    ROLE_TP
} enclave_role_e;

// this function should be called for every entry point into the enclave
// it will abort the enclave in case of conflicts, if the same instance of the enclave is used for multiple purposes
void verify_enclave_role(enclave_role_e role);

#endif // _ENCLAVE_ROLE_H_
