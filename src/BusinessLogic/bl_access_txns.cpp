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

#include "algorithm"
#include "bl_access_txns.h"
#include "access_control.h"
#include "acl_read_write.h"
#include "enclave_log.h"
#include <stdio.h>
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

bool is_acl_txn(const secure::string &payload)
{
    try
    {
        auto json = nlohmann::json::parse(payload);
        if (json.find(config::type_str) != json.end())
        {
            auto type = json.at(config::type_str).get<std::string>();
            if (type == config::ACL_TRANSACTION_TYPE)
            {
                return true;
            }
        }
        return false;
    }
    catch (const std::exception &e)
    {
        PRINT(ERROR, LOGIC, "exception when trying to parse txn payload as json\n");
        PRINT(INFO, LOGIC, "%s\n", e.what());
        return false;
    }
}

//extract params from json payload
bool extract_params_json(const secure::string &payload,
                         config::ActionType &action,
                         secure::vector<SignerPubKey> &keys,
                         secure::vector<secure::string> &addresses,
                         secure::string &group,
                         uint16_t &new_svn)
{
    try
    {
        auto json = nlohmann::json::parse(payload);

        //get action
        action = get_acl_action(json.at(config::action_str).get<secure::string>());
        if (action == config::ActionType::INVALID)
        {
            PRINT(ERROR, LOGIC, "invalid action type %s\n", json.at(config::action_str).get<secure::string>().c_str());
            return false;
        }

        //get keys from array
        auto keys_arr = json.at(config::key_str);
        for (const auto k : keys_arr)
        {
            auto key_str = k.get<secure::string>();
            if (key_str.size() != PUB_KEY_LENGTH - 1)
            {
                PRINT(ERROR, LOGIC, "key %s is invalid, expected key of size %d\n",
                      key_str.c_str(), PUB_KEY_LENGTH - 1);
                return false;
            }
            // copy key string to SignerPubKey and push it to keys vec
            auto key_res = getKeyFromStr(key_str);
            if (!key_res.first)
                return false;
            keys.push_back(key_res.second);
        }

        //get addresses from array if exists
        if (json.find(config::address_str) != json.end())
        {
            auto addr_arr = json.at(config::address_str);
            for (const auto a : addr_arr)
            {
                auto addr_str = a.get<secure::string>();
                if (addr_str.size() > sizeof(StlAddress))
                {
                    PRINT(ERROR, LOGIC, "address %s is invalid, address size is bigger than %d\n", addr_str.c_str(), 70);
                    return false;
                }
                //push address to addresses vector
                addresses.push_back(addr_str);
            }
        }

        //get group if exists
        if (json.find(config::group_str) != json.end())
        {
            group = json.at(config::group_str).get<secure::string>();
        }

        // get svn, should only be relevant if action is to update svn
        if (json.find(config::new_svn_str) != json.end())
        {
            auto x = json.at(config::new_svn_str).get<int>();
            if (x < 0 || x > std::numeric_limits<uint16_t>::max())
            {
                PRINT(ERROR, LOGIC, "new svn %d is not a valid uint16_t\n", x);
                return false;
            }
            new_svn = static_cast<uint16_t>(x);
        }
        return true;
    }
    catch (const std::exception &e)
    {
        PRINT(ERROR, LOGIC, "exception when trying to parse txn payload as json\n");
        PRINT(INFO, LOGIC, "%s\n", e.what());
        return false;
    }
}

// convert action string to action type enum so it can be used in switch case statement
config::ActionType get_acl_action(const secure::string &action)
{
    {
        if (action == config::action_add_group_str.c_str())
            return config::ActionType::ADD_GROUP;
        if (action == config::action_add_member_str.c_str())
            return config::ActionType::ADD_MEMBER;
        if (action == config::action_remove_group_str.c_str())
            return config::ActionType::REMOVE_GROUP;
        if (action == config::action_remove_member_str.c_str())
            return config::ActionType::REMOVE_MEMBER;
        if (action == config::action_add_access_str.c_str())
            return config::ActionType::ADD_ACCESS;
        if (action == config::action_add_to_group_str.c_str())
            return config::ActionType::ADD_TO_GROUP;
        if (action == config::action_remove_access_str.c_str())
            return config::ActionType::REMOVE_ACCESS;
        if (action == config::action_remove_from_group_str.c_str())
            return config::ActionType::REMOVE_FROM_GROUP;
        if (action == config::action_change_member_key_str.c_str())
            return config::ActionType::CHANGE_MEMBER_KEY;
        if (action == config::action_update_svn_str.c_str())
            return config::ActionType::UPDATE_SVN;
        return config::ActionType::INVALID;
    }
}

bool do_acl_action(const secure::string &payload, const SignerPubKey &signerPubKey, const uint16_t &svn, const secure::string &nonce)
{

    config::ActionType action;
    secure::vector<SignerPubKey> keys;
    secure::vector<secure::string> addresses;
    secure::string group = "";
    uint16_t update_svn = 0;
    if (!extract_params_json(payload, action, keys, addresses, group, update_svn))
        return false;

    //must be admin unless it is change key txn
    if (signerPubKey != acl::get_admin_key() && action != config::ActionType::CHANGE_MEMBER_KEY)
    {
        PRINT(ERROR, LOGIC, "ERROR! non-admin signer public key :%s is trying to change access list\n", signerPubKey.data());
        return false;
    }
    switch (action)
    {
    case config::ActionType::ADD_GROUP:
    {
        // TODO move to seperate function
        // convert group string to group ID
        // GroupID g_id;
        // try
        // {
        //     g_id = std::stoull(group.c_str());
        // }
        // catch (const std::invalid_argument &ia)
        // {
        //     PRINT(ERROR, LOGIC, "invalid argument error when converting group key %s to uint64_t\n", group.c_str());
        //     return false;
        // }
        // catch (const std::out_of_range &oor)
        // {
        //     PRINT(ERROR, LOGIC, "out of range error when converting group key %s to uint64_t\n", group.c_str());
        //     return false;
        // }
        // if (!acl::create_group(g_id))
        // {
        //     return false;
        // }
        // // get address if exists
        // if (!addresses.empty())
        // {
        //     // TODO
        //     // get address as StlAddress with prefix...
        //     // add access to group
        //     // return acl::allow_group_access(addr, g_id, prefix_len);
        // }
        return true;
    }
    case config::ActionType::REMOVE_GROUP:
    {
        // TODO
        // get group name
        // remove group
        // remove group access?
        return true;
    }
    case config::ActionType::ADD_MEMBER:
    {
        // add members
        if (keys.size() < 1)
        {
            PRINT(ERROR, LOGIC, "action add member requires at least one member key\n");
            return false;
        }
        // get Address if exist
        if (addresses.size() > 0)
        {
            if (addresses.size() != keys.size())
            {
                PRINT(ERROR, LOGIC, "addresses array size must be the same size as keys size\n");
                return false;
            }
            // add access to member will add members if not exist
            if (!acl::add_access_to_members(addresses, keys, svn, nonce))
            {
                PRINT(ERROR, LOGIC, "acl add_access_to_members failure\n");
                return false;
            }
        }
        else // no addresses, just add members
        {
            if (!acl::add_members(keys, svn, nonce))
            {
                PRINT(ERROR, LOGIC, "acl add_members failure\n");
                return false;
            }
        }
        // TODO
        // get group if exists
        // add member to group
        return true;
    }
    case config::ActionType::REMOVE_MEMBER:
    {
        if (keys.size() < 1)
        {
            PRINT(ERROR, LOGIC, "action remove member requires at least one member key\n");
            return false;
        }
        if (!acl::remove_members(keys, svn, nonce))
        {
            PRINT(ERROR, LOGIC, "acl remove_members failure\n");
            return false;
        }
        return true;
    }
    case config::ActionType::ADD_ACCESS:
    {
        if (keys.size() != 1)
        {
            PRINT(ERROR, LOGIC, "action add access requires exactly one member key\n");
            return false;
        }
        if (!acl::acl_is_member(keys.front(), svn, true))
        {
            PRINT(ERROR, LOGIC, "trying to add access but member doens't exist\n");
            return false;
        }
        // get Address if exist
        if (addresses.size() == 0)
        {
            PRINT(ERROR, LOGIC, "trying to add access but member doens't exist\n");
            return false;
        }

        // add access to member
        if (!acl::add_access_to_members(addresses, keys, svn, nonce))
        {
            PRINT(ERROR, LOGIC, "acl add_access_to_members failure\n");
            return false;
        }

        // TODO
        // get group if exists
        // add access to group
        return true;
    }
    case config::ActionType::REMOVE_ACCESS:
    {
        if (keys.size() != 1)
        {
            PRINT(ERROR, LOGIC, "action remove access requires exactly one member key\n");
            return false;
        }
        if (!acl::acl_is_member(keys.front(), svn, true))
        {
            PRINT(ERROR, LOGIC, "trying to remove access but member doens't exist\n");
            return false;
        }
        // get Address if exist
        if (addresses.size() == 0)
        {
            PRINT(ERROR, LOGIC, "trying to remove access but member doens't exist\n");
            return false;
        }

        // remove access to member
        if (!acl::remove_access_from_member(addresses, keys.front(), svn, nonce))
        {
            PRINT(ERROR, LOGIC, "acl add_access_to_members failure\n");
            return false;
        }

        // TODO
        // get group if exists
        // add access to group
        return true;
    }
    case config::ActionType::ADD_TO_GROUP:
    {
        // TODO
        // get member
        // get group
        // add member to group
        return true;
    }
    case config::ActionType::REMOVE_FROM_GROUP:
    {
        // TODO
        // get member public key
        // get group
        // remove member from group
        return true;
    }
    case config::ActionType::CHANGE_MEMBER_KEY:
    {
        // if one key than change singer public key to new key
        // if 2 keys than change key 1 to key 2 (must be signed by admin)
        SignerPubKey old_key, new_key;
        if (keys.size() == 1)
        {
            old_key = signerPubKey;
            new_key = keys[0];
        }
        else if (keys.size() == 2 && signerPubKey == acl::get_admin_key())
        {
            old_key = keys[0];
            new_key = keys[1];
        }
        else
        {
            PRINT(ERROR, LOGIC, "action change member key requires one key or 2 if signed by admin\n");
            return false;
        }

        if (!acl::change_member_key(old_key, new_key, svn, nonce))
        {
            PRINT(ERROR, LOGIC, "acl change_member_key failure\n");
            return false;
        }
        return true;
    }
    case config::ActionType::UPDATE_SVN:
    {
        if (!acl::update_svn(update_svn, svn, nonce))
        {
            PRINT(ERROR, LOGIC, "update svn failed\n");
            return false;
        }
        return true;
    }
    case config::ActionType::INVALID:
    {
        PRINT(ERROR, LOGIC, "action is invalid\n");
        return false;
    }
    default:
    {
        PRINT(ERROR, LOGIC, "do_acl_action error\n");
        return false;
    }
    }
}

} // namespace business_logic