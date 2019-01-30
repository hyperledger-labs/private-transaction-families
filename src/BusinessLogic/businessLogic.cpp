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
#include <stdexcept>
#include <algorithm>
#include "businessLogic.h"
#include "bl_internal.h"
#include "bl_access_txns.h"
#include "access_control.h"
#include "acl_read_write.h"
#include "config.h"
#include "TasePoc.h"
#include "crypto.h"
#include "enclave_log.h"
#include "secure_allocator.h"
#include "json.hpp"

// add secure string support to json parser
namespace nlohmann
{
template <>
struct adl_serializer<secure::string>
{
    static void to_json(json &j, const secure::string &value)
    {
        j = std::string(value.c_str()); // calls to_json with std string
    }

    static void from_json(const json &j, secure::string &value)
    {
        value = secure::string(j.get<std::string>().c_str());
    }
};
} // namespace nlohmann


namespace business_logic
{

bool payloadToParams(const secure::string &payload, secure::string &verb, secure::string &name, int &value, int &addr_len, secure::string &prefix)
{

    try
    {
        PRINT(INFO, LOGIC, "paylaod is %s\n", payload.c_str());
        auto json = nlohmann::json::parse(payload);
        json.at("Verb").get_to(verb);
        json.at("Name").get_to(name);
        if (name.length() == 0 || name.length() > 128)
        {
            PRINT(INFO, LOGIC, "Name is invalid, name must be between 1 and 128 characters in length\n");
            return false;
        }
        json.at("Value").get_to(value);
        if (json.find("Size") != json.end())
        {
            json.at("Size").get_to(addr_len);
            if (addr_len < 0)
            {
                PRINT(INFO, LOGIC, "Size cannot be smaller than 0\n");
                return false;
            }
        }
        else
            addr_len = 0;
        if (json.find("Prefix") != json.end())
        {
            json.at("Prefix").get_to(prefix);
            if (prefix.length() > 70)
            {
                PRINT(INFO, LOGIC, "Prefix is invalid, prefix can't be longer than address size (70)\n");
                return false;
            }
        }
        else
            prefix = "";

        return true;
    }
    catch (const std::exception &e)
    {
        PRINT(ERROR, LOGIC, "exception when trying to parse txn payload as json\n");
        PRINT(INFO, LOGIC, "%s\n", e.what());
        return false;
    }
};

StlAddress getAddress(const secure::string &name, const secure::string &prefix, const SignerPubKey &signerPubKey)
{
    sha512_data_t shaRes = {};
    StlAddress addr = {};
    auto prefix_len = prefix.size();
    if (prefix.empty())
    {
        config::get_prefix().copy(addr.address_32_32.family.data(), addr.address_32_32.family.size());

        if (!sha512_msg((const uint8_t *)signerPubKey.data(), PUB_KEY_LENGTH, &shaRes))
        {
            PRINT(ERROR, LOGIC, "failed to calculate signer key hash, throwing!!!\n")
            throw std::runtime_error("failed to calculate signer key hash");
        }
        secure::string str = ToHexString(shaRes.data, addr.address_32_32.member_id.size() / 2);
        str.copy(addr.address_32_32.member_id.data(), addr.address_32_32.member_id.size());
        prefix_len = addr.address_32_32.family.size() + addr.address_32_32.member_id.size();
    }
    else
    {
        prefix.copy(addr.val.data(), prefix_len);
    }
    shaRes = {};
    if (!sha512_msg(secure::vector<uint8_t>(name.begin(), name.end()).data(), name.length(), &shaRes))
    {
        PRINT(ERROR, LOGIC, "failed to calculate address key hash, throwing!!!\n")
        throw std::runtime_error("failed to calculate address key hash");
    }
    secure::string str = ToHexString(shaRes.data, (addr.val.size() - prefix_len) / 2);
    str.copy(addr.val.data() + prefix_len, addr.val.size() - 1 - prefix_len);

    addr.properties.null_terminator[0] = '\0';
    return addr;
}

// Handle an IntKey 'set' verb action. This sets a IntKey value to
// the given value.
bool DoSet(const secure::string &name, const int value, const int addr_len, const secure::string &prefix, const SignerPubKey &signerPubKey, const uint16_t &svn, const secure::string &nonce)
{
    PRINT(INFO, LOGIC, "IntKeyApplicator::DoSet Name: %s Value: %d \n", name.c_str(), value);
    StlAddress addr;
    try
    {
        addr = getAddress(name, prefix, signerPubKey);
    }
    catch (...)
    {
        return false;
    }
    secure::vector<uint8_t> state_value;
    if (!acl::acl_read(addr, signerPubKey, state_value, svn))
    {
        PRINT(ERROR, LOGIC, "acl read returened failure\n");
        return false;
    }
    nlohmann::json json;
    if (state_value.size() != 0)
    { // not empty address
        try
        {
            json = nlohmann::json::from_cbor(state_value);
            if (json.find(name.c_str()) != json.end())
            {
                PRINT(INFO, LOGIC, " Verb was 'Set', but name %s already exists\n", name.c_str());
                return false;
            }
        }
        catch (const std::exception &e)
        {
            PRINT(ERROR, LOGIC, "failed to parse state data as json\n");
            PRINT(INFO, LOGIC, "%s\n", e.what());
            return false;
        }
    }
    // add padding
    if (addr_len > 0)
    {
        secure::string padding_str(addr_len, 'x');
        json["padding"] = padding_str;
    }
    // add "key : value"
    json[name.c_str()] = value;
    auto cbor = nlohmann::json::to_cbor(json);
    secure::vector<uint8_t> secure_cbor(std::begin(cbor), std::end(cbor));
    if (FAILED(acl::acl_write(addr, signerPubKey, secure_cbor, svn, nonce)))
    {
        PRINT(INFO, LOGIC, "Write to addr %s failed\n", addr.val.data());
        return false;
    }
    return true;
}
// Handle an IntKey 'inc' and 'dec' verb action. This increments an IntKey value
// stored in global state by a given value.
bool DoIncDec(const secure::string &name, const int value, const secure::string &prefix, const SignerPubKey &signerPubKey, const uint16_t &svn, const secure::string &nonce)
{
    PRINT(INFO, LOGIC, "IntKeyApplicator::DoInc/Dec Name: %s Value: %d \n", name.c_str(), value);
    secure::vector<StlAddress> addresses;
    if (!acl::acl_read_prefix(prefix, signerPubKey, addresses, svn))
    {
        PRINT(ERROR, LOGIC, "acl read prefix returened failure\n");
        return false;
    }
    if (addresses.empty())
    {
        PRINT(INFO, LOGIC, " acl read prefix returned empty vector\n");
        return false;
    }
    if (!acl::acl_delete(addresses, signerPubKey, svn))
    {
        PRINT(INFO, LOGIC, "acl delte failed\n");
        return false;
    }
    return true;
    // StlAddress addr;
    // try
    // {
    //     addr = getAddress(name, prefix, signerPubKey);
    // }
    // catch (...)
    // {
    //     return false;
    // }
    // secure::vector<uint8_t> state_value;
    // if (!acl::acl_read(addr, signerPubKey, state_value, svn))
    // {
    //     PRINT(ERROR, LOGIC, "acl read returened failure\n");
    //     return false;
    // }
    // if (state_value.size() == 0)
    // {
    //     PRINT(INFO, LOGIC, " Verb was 'Inc/Dec', but address not found\n");
    //     return false;
    // }
    // // not empty address
    // try
    // {
    //     auto json = nlohmann::json::from_cbor(state_value);
    //     if (json.find(name.c_str()) == json.end())
    //     {
    //         PRINT(INFO, LOGIC, "Verb was 'Inc/Dec', but value does not exists\n");
    //         return false;
    //     }
    //     auto val = json[name.c_str()].get<int>();
    //     val += value;
    //     json[name.c_str()] = val;
    //     auto cbor = nlohmann::json::to_cbor(json);
    //     secure::vector<uint8_t> secure_cbor(std::begin(cbor), std::end(cbor));
    //     if (FAILED(acl::acl_write(addr, signerPubKey, secure_cbor, svn, nonce)))
    //     {
    //         PRINT(INFO, LOGIC, "Write to addr %s failed\n", addr.val.data());
    //         return false;
    //     }
    //     return true;
    // }
    // catch (const std::exception &e)
    // {
    //     PRINT(ERROR, LOGIC, "failed to parse state data as json\n");
    //     PRINT(INFO, LOGIC, "%s\n", e.what());
    //     return false;
    // }
}

bool execute_transaction(const secure::string &payload, const SignerPubKey &signerPubKey, const uint16_t &svn, const secure::string &nonce)
{
    if (business_logic::is_acl_txn(payload))
    {
        return do_acl_action(payload, signerPubKey, svn, nonce);
    }

    // TODO add implementation here ...
    secure::string verb;
    secure::string name;
    secure::string prefix;
    int value;
    int addr_len;
    if (!payloadToParams(payload, verb, name, value, addr_len, prefix))
        return false;

    if (verb == "set")
    {
        return DoSet(name, value, addr_len, prefix, signerPubKey, svn, nonce);
    }
    else if (verb == "inc" || verb == "dec")
    {
        if (verb == "dec")
        {
            value = -value;
        }
        return DoIncDec(name, value, prefix, signerPubKey, svn, nonce);
    }
    else
    {
        PRINT(INFO, LOGIC, "invalid Verb %s\n", verb.c_str());
        return false;
    }
}

bool bl_read(const StlAddress &addr, const SignerPubKey &key, secure::string *out_value, const uint16_t &svn)
{
    secure::vector<uint8_t> data_vec;
    if (!acl::acl_read(addr, key, data_vec, svn, true))
        return false;
    if (data_vec.empty())
    {
        *out_value = "";
        return true;
    }
    try
    {
        auto json = nlohmann::json::from_cbor(data_vec);
        *out_value = json.dump().c_str();
        return true;
    }
    catch (const std::exception &e)
    {
        PRINT(ERROR, LOGIC, "failed to parse state data as json, showing as hex string\n");
        PRINT(INFO, LOGIC, "%s\n", e.what());
        *out_value = ToHexString(data_vec.data(), data_vec.size());
        return true;
    }
}

} // namespace business_logic