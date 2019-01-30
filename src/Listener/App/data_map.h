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

#pragma once
#include <string>
#include <mutex>
#include <map>
#include <vector>

namespace listener
{
//singltone class for handling data read from sawtooth
// read ocall with size 0 will store data and return data size,
// read with exact data size will return data and erase it
class DataMap final
{
public:
	// delete copy and move constructors and assign operators
	DataMap(DataMap const &) = delete;						// Copy construct
	DataMap(DataMap &&) = delete;									// Move construct
	DataMap &operator=(DataMap const &) = delete; // Copy assign
	DataMap &operator=(DataMap &&) = delete;			// Move assign
	static DataMap &Instance();
	std::pair<bool, uint32_t> push_data(const std::string &data);
	std::pair<bool, uint32_t> push_data(const std::vector<std::string> &data_vec);

	std::string pop_data(const uint32_t id);

private:
	DataMap();
	~DataMap();
	std::mutex data_map_mutex;
	std::map<uint32_t, std::string> data_id_map;
	uint32_t next_id;
};

} // namespace listener
