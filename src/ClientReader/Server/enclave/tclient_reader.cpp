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


#include <stdio.h>

#include "secure_allocator.h"
#include "enclave_log.h"
#include "crypto_kdf_strings.h"
#include "crypto_enclave.h"
#include "crypto_ledger_reader_writer.h"
#include "PrivateLedger.h"
#include "acl_read_write.h"
#include "ledger_keys.h"
#include "tclient_reader.h"
#include "tmemory_debug.h" // only have effect in DEBUG mode

#include "Enclave_t.h"
#include <memory>


Tclient_Reader_Data_Map::Tclient_Reader_Data_Map()
{
	next_id = 1;
	lock = SGX_SPINLOCK_INITIALIZER;
}

Tclient_Reader_Data_Map::~Tclient_Reader_Data_Map()
{
	data_id_map.clear();
	
	//memset_s(&ledger_keys, sizeof(ledger_keys_t), 0, sizeof(ledger_keys_t));
}
	
uint64_t Tclient_Reader_Data_Map::add_data(secure::string data)
{
	uint64_t id = 0;
	
	sgx_spin_lock(&lock);
	
	try {
	
	id = next_id++;
	data_id_map[id] = data;
	
	} catch (...)
	{
		PRINT(ERROR, SERVER, "failed to add object to map!\n");
	}
	
	sgx_spin_unlock(&lock);
	
	return id;
}

secure::string Tclient_Reader_Data_Map::get_data(uint64_t id)
{
	secure::string ret;
	
	sgx_spin_lock(&lock);
	
	if (data_id_map.find(id) == data_id_map.end())
	{
		sgx_spin_unlock(&lock);
		return ret;
	}

	ret = data_id_map[id];
	data_id_map.erase(id);
	
	sgx_spin_unlock(&lock);
	
	return ret;
}

// // single global instance


