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
#include "PrivateLedger.h"

namespace config
{
extern std::string g_key_path; // ledger keys path
extern std::string g_rest_url; // url of rest api

std::string get_namespace();
std::string get_version();
std::string get_prefix();
SignerPubKey get_admin_key();

// following configuration will only be used while processing acl txns
// so no need to worry about static initialization fiasco

// fields used for special 'change ACL' transaction
const static std::string type_str = "Type";
const static std::string action_str = "Action";
const static std::string key_str = "Key";
const static std::string address_str = "Address";
const static std::string group_str = "Group";
const static std::string new_svn_str = "new_svn";
const static std::string action_add_member_str = "add_member";
const static std::string action_add_group_str = "add_group";
const static std::string action_add_to_group_str = "add_to_group";
const static std::string action_add_access_str = "add_access";
const static std::string action_remove_member_str = "remove_member";
const static std::string action_remove_group_str = "remove_group";
const static std::string action_remove_from_group_str = "remove_from_group";
const static std::string action_remove_access_str = "remove_access";
const static std::string action_change_member_key_str = "change_member_key";
const static std::string action_update_svn_str = "update_svn";
static const std::string ACL_TRANSACTION_TYPE = "private_ledger_administration";
enum ActionType{
    ADD_MEMBER,
    ADD_GROUP,
    ADD_ACCESS,
    ADD_TO_GROUP,
    REMOVE_MEMBER,
    REMOVE_GROUP,
    REMOVE_ACCESS,
    REMOVE_FROM_GROUP,
    CHANGE_MEMBER_KEY,
    UPDATE_SVN,
    INVALID
};

} // namespace config
