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
 
#include <map> // stl std::map

#include <sgx_thread.h> // mutex

#include "server_session.h"
#include "tmemory_debug.h" // only have effect in DEBUG mode

// todo - use singleton class
// todo - think about DOS prevention

static sgx_thread_mutex_t g_sessions_mutex = SGX_THREAD_MUTEX_INITIALIZER;
static uint64_t g_session_id = 1; // start from 1, if we reach 0 - kill the enclave
static std::map<uint64_t, session_t*> g_sessions;


uint64_t add_session(session_t* session)
{
	uint64_t session_id = 0;
	
	sgx_thread_mutex_lock(&g_sessions_mutex);
	try {
		if (g_session_id == ULLONG_MAX)
			abort(); // attack of some sort, kill the enclave!
			
		g_sessions[g_session_id] = session;
		session_id = g_session_id++;
	}
	catch(...)	{
		session_id = 0;
	}
	sgx_thread_mutex_unlock(&g_sessions_mutex);
	
	return session_id;
}


session_t* get_session(uint64_t session_id)
{
	std::map<uint64_t,session_t*>::iterator it;
	
	sgx_thread_mutex_lock(&g_sessions_mutex);
    it = g_sessions.find(session_id);
    sgx_thread_mutex_unlock(&g_sessions_mutex);
    if (it == g_sessions.end())
		return NULL;
	return it->second;
}


void free_session(uint64_t session_id)
{
	session_t* session = NULL;
	std::map<uint64_t,session_t*>::iterator it;
	
	sgx_thread_mutex_lock(&g_sessions_mutex);
    it = g_sessions.find(session_id);
    if (it == g_sessions.end())
    {
		sgx_thread_mutex_unlock(&g_sessions_mutex);
		return;
	}
	
	session = it->second;
	g_sessions.erase(it);
	sgx_thread_mutex_unlock(&g_sessions_mutex);
	
	if (session == NULL)
		return;
	
    if (session->sig_rl != NULL)
		free(session->sig_rl);
		
	memset_s(session, sizeof(session_t), 0, sizeof(session_t)); // scrub all the secret session keys
		
    free(session);
}

