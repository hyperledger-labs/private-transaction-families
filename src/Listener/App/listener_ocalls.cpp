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

#include "Enclave_u.h"
#include "app_log.h"
#include "data_map.h"
#include "exceptions.h"  // sawtooth exception
#include "rest_handler.h"
#include "txn_handler.h"

using namespace listener;

const int addr_len = 70;
// return -1 on failure, else size of read data, if data_size is 0 then don't
// fill value
int SGX_CDECL tl_call_stl_read_cr(uint32_t *id, const char *addr, char *value,
                                  uint32_t data_size) {
    if (id == NULL || addr == NULL || (data_size != 0 && value == NULL)) {
        PRINT(ERROR, LISTENER, "invalid arguments\n");
        return -1;
    }
    const std::string address(addr, addr_len);
    if (address.size() != addr_len) {
        PRINT(ERROR, LISTENER, "invalid address size\n");
        return -1;
    }
    std::string data;
    if (data_size == 0) {
        PRINT(INFO, LISTENER, "read from sawtooth rest api address %s\n",
              address.c_str())
        // read from client reader won't have context, read via rest API
        // get state, push data, return data size and id
        RestHandler handler;
        data = handler.read_from_rest_api(address);
        if (data.empty())  // address doesn't contain data
        {
            return 0;
        }
        auto res = DataMap::Instance().push_data(data);
        if (!res.first) {
            return -1;
        }
        *id = res.second;
        return data.length();
    }
    // if data_size != 0, pop data at givev id
    data = DataMap::Instance().pop_data(*id);
    if (data_size < data.length()) {
        PRINT(ERROR, LISTENER, "not enough memory to read from sawtooth\n");
        return -1;
    }
    data.copy(value, data.length());
    value[data.length()] = '\0';
    return data.length();
}

// return -1 on failure, else size of read data, if data_size is 0 then don't
// fill value
int SGX_CDECL tl_call_stl_read(uint32_t *id, const char *addr, char *value,
                               uint32_t data_size) {
    if (id == NULL || addr == NULL || (data_size != 0 && value == NULL)) {
        PRINT(ERROR, LISTENER, "invalid arguments\n");
        return -1;
    }
    const std::string address(addr, addr_len);
    if (address.size() != addr_len) {
        PRINT(ERROR, LISTENER, "invalid address size\n");
        return -1;
    }
    std::string data;

    if (data_size == 0) {
        PRINT(INFO, LISTENER, "read from sawtooth address %s\n",
              address.c_str())
        // get state, push data, return data size and id
        try  // surround with try/catch since sawtooth getState can throw
        {
            if (!txn_handler::contextPtr->GetState(&data, address)) {
                PRINT(ERROR, LISTENER, "sawtooth get state failed\n");
                return -1;
            }
            if (data.empty())  // address doesn't contain data
            {
                return 0;
            }
            auto res = DataMap::Instance().push_data(data);
            if (!res.first) {
                return -1;
            }
            *id = res.second;
            return data.length();
        } catch (const sawtooth::InvalidTransaction &e) {
            PRINT(ERROR, LISTENER, "InvalidTransaction, %s\n", e.what());
            return -1;
        } catch (...) {
            PRINT(ERROR, LISTENER,
                  "sawtooth get state failed throwed exception\n");
            return -1;
        }
    }
    // if data_size != 0, pop data at givev id
    data = DataMap::Instance().pop_data(*id);
    if (data_size < data.length()) {
        PRINT(ERROR, LISTENER, "not enough memory to read from sawtooth\n");
        return -1;
    }
    data.copy(value, data.length());
    value[data.length()] = '\0';
    return data.length();
}

sgx_status_t SGX_CDECL tl_call_stl_write(const char *addr,
                                         size_t num_of_address,
                                         const char *value, size_t data_size) {
    if (addr == NULL || value == NULL || num_of_address < 1) {
        PRINT(ERROR, LISTENER, "invalid arguments\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }
    // build vector of addresses and values: 
    // Each address is 70 charecters, values are sperated by '\0'
    std::vector<std::pair<std::string, std::string>> addr_val_vec = {};
    addr_val_vec.reserve(num_of_address);

    const char(*addr_arr)[addr_len] = (const char(*)[addr_len])addr;
    size_t value_size = 0, total_size = 0;
    for (int i = 0; i < (int)num_of_address; i++) {
        // get address
        std::string address = std::string(addr_arr[i], addr_arr[i + 1]);
        if (address.size() != addr_len) {
            PRINT(ERROR, LISTENER, "invalid address size\n");
            return SGX_ERROR_INVALID_PARAMETER;
        }
        // get value
        std::string value_str = std::string(value);
        value_size = value_str.size();
        value += value_size + 1; // skip '\0'
        total_size += value_size +1;
        if (total_size > data_size+1)
        {
            PRINT(ERROR, LISTENER, "invalid data size\n");
            PRINT(INFO, LISTENER, "value_size %zd, total_size %zd, data_size %zd\n", value_size, total_size, data_size);
            return SGX_ERROR_INVALID_PARAMETER;
        }
        // add address and value to vector
        PRINT(INFO, LISTENER, "write %zd bytes to sawtooth address %s\n",
              value_size, address.c_str());
        addr_val_vec.emplace_back(std::make_pair(address, value_str));
    }
    try {
        txn_handler::contextPtr->SetState(addr_val_vec);
        return SGX_SUCCESS;
    } catch (...) {
        PRINT(ERROR, LISTENER, "sawtooth set state failed\n");
        return SGX_ERROR_UNEXPECTED;
    }
}

sgx_status_t SGX_CDECL tl_call_stl_delete(const char *addresses,
                                          size_t num_of_address) {
    if (addresses == NULL) {
        PRINT(ERROR, LISTENER, "invalid arguments\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }
    try {
        // build vector of addresses, each address is 70 charecters
        const char(*addr_arr)[addr_len] = (const char(*)[addr_len])addresses;
        std::vector<std::string> addr_vec;
        addr_vec.reserve(num_of_address);
        for (int i = 0; i < (int)num_of_address; i++) {
            std::string address = std::string(addr_arr[i], addr_arr[i + 1]);
            addr_vec.emplace_back(address);
            PRINT(INFO, LISTENER, "delete from sawtooth address %s\n",
                  address.c_str())
        }
        txn_handler::contextPtr->DeleteState(addr_vec);
        return SGX_SUCCESS;
    } catch (...) {
        PRINT(ERROR, LISTENER, "sawtooth delete state failed\n");
        return SGX_ERROR_UNEXPECTED;
    }
    return SGX_SUCCESS;
}
