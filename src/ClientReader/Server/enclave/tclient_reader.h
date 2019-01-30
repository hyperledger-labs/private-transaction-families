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


#ifndef _TCLIENT_READER_H_
#define _TCLIENT_READER_H_

#include <map>
#include <sgx_spinlock.h>

class Tclient_Reader_Data_Map
{
private:
	sgx_spinlock_t lock;

// data section
	std::map<uint64_t, secure::string> data_id_map = {};
	uint64_t next_id;
		
public:
	Tclient_Reader_Data_Map();
	~Tclient_Reader_Data_Map();
	
	uint64_t add_data(secure::string data);
	secure::string get_data(uint64_t id);
};

#endif // _TCLIENT_READER_H_
