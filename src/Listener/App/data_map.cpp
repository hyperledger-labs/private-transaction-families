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

#include "data_map.h"
#include "app_log.h"

namespace listener
{

// DataMap
DataMap &DataMap::Instance()
{
    static DataMap dataSingletonInstance;
    return dataSingletonInstance;
}

DataMap::DataMap()
{
    data_id_map = {};
    next_id = 0;
}

DataMap::~DataMap()
{
}

std::pair<bool, uint32_t> DataMap::push_data(const std::string &data)
{
    // lock mutex, the mutex is released when guard gets out of scope
    std::lock_guard<std::mutex> guard(data_map_mutex);
    try
    {
        // increase id, after max uint, id will start again from zero,
        // assuming that data with such old id's if exists can be erased
        uint32_t id = next_id++;
        //push data, replacing old data if allready exists
        data_id_map[id] = data;
        return std::make_pair(true, id);
    }
    catch (...)
    {
        PRINT(ERROR, LISTENER, "failed to add object to map!\n");
        return std::make_pair(false, 0);
    }
}

std::pair<bool, uint32_t> DataMap::push_data(const std::vector<std::string> &data_vec)
{
    // lock mutex, the mutex is released when guard gets out of scope
    std::lock_guard<std::mutex> guard(data_map_mutex);
    try
    {
        // increase id, after max uint, id will start again from zero,
        // assuming that data with such old id's if exists can be erased
        uint32_t id = next_id++;
        std::string data_str= "";
        for(const auto & data : data_vec)
        {
            data_str.append(data);
        }
        //push data, replacing old data if allready exists
        data_id_map[id] = data_str;
        return std::make_pair(true, id);
    }
    catch (...)
    {
        PRINT(ERROR, LISTENER, "failed to add object to map!\n");
        return std::make_pair(false, 0);
    }
}

std::string DataMap::pop_data(const uint32_t id)
{
    // lock mutex, the mutex is released when guard gets out of scope
    std::lock_guard<std::mutex> guard(data_map_mutex);

    auto it = data_id_map.find(id);
    if (it == data_id_map.end())
    {
        return "";
    }
    std::string ret = it->second;
    data_id_map.erase(it);

    return ret;
}
} // namespace listener
