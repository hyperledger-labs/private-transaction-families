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

int SGX_CDECL tl_call_stl_read_prefix(uint32_t *id, const char *addr_prefix,
                                      char *value, uint32_t num_of_addr) {
    if (id == NULL || addr_prefix == NULL ||
        (num_of_addr != 0 && value == NULL)) {
        PRINT(ERROR, LISTENER, "invalid arguments\n");
        return -1;
    }
    const std::string address(addr_prefix);
    if (address.size() > addr_len) {
        PRINT(ERROR, LISTENER, "invalid address size\n");
        return -1;
    }
    std::vector<std::string> addr_vec;

    if (num_of_addr == 0) {
        PRINT(INFO, LISTENER, "read from sawtooth address %s\n",
              address.c_str())
        // get state, push data, return data size and id
        try  // surround with try/catch since sawtooth can throw
        {
            txn_handler::contextPtr->ListAddresses(&addr_vec, address);
            if (addr_vec.size() ==0)  // no addresses for this prefix
            {
                PRINT(ERROR, LISTENER, "no addresses with this prefix\n");
                return 0;
            }

            auto res = DataMap::Instance().push_data(addr_vec);
            if (!res.first) {
                return -1;
            }
            *id = res.second;
            return addr_vec.size();
        } catch (const sawtooth::InvalidTransaction &e) {
            PRINT(ERROR, LISTENER, "InvalidTransaction, %s\n", e.what());
            return -1;
        } catch (...) {
            PRINT(ERROR, LISTENER,
                  "sawtooth get state failed throwed exception\n");
            return -1;
        }
    }
    // if num_of_addr != 0, pop data at givev id
    std::string data = DataMap::Instance().pop_data(*id);
    if (num_of_addr*addr_len < data.length()) {
        PRINT(ERROR, LISTENER, "not enough memory to read from sawtooth\n");
        return -1;
    }
    data.copy(value, data.length());
    value[data.length()] = '\0';
    return data.length()/addr_len;
}

sgx_status_t SGX_CDECL tl_call_stl_write(const char *addr, const char *value,
                                         size_t data_size) {
    if (addr == NULL || value == NULL) {
        PRINT(ERROR, LISTENER, "invalid arguments\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }
    const std::string address(addr, addr_len);
    if (address.size() != addr_len) {
        PRINT(ERROR, LISTENER, "invalid address size\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }
    PRINT(INFO, LISTENER, "write %zd bytes to sawtooth address %s\n", data_size,
          address.c_str());
    const std::string data(value, data_size);
    try {
        txn_handler::contextPtr->SetState(address, data);
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
