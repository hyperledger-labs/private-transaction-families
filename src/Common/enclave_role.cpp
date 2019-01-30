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
 
 #include <stdlib.h>
#include <sgx_spinlock.h>

#include "enclave_role.h"
#include "enclave_log.h"

enclave_role_e g_role = ROLE_NONE;
sgx_spinlock_t g_role_lock = SGX_SPINLOCK_INITIALIZER;

// this function will abort the enclave in case of conflicts
void verify_enclave_role(enclave_role_e role)
{
	if (role == ROLE_NONE)
		abort(); // attack?
		
	sgx_spin_lock(&g_role_lock);
	if (g_role == ROLE_NONE)
	{
		g_role = role;
	}
	sgx_spin_unlock(&g_role_lock);
	
	if (g_role == role)
	{
		return;
	}
	
	PRINT(ERROR, NONE, "conflicting enclave roles, aborting enclave!\n");
	abort();	
}
