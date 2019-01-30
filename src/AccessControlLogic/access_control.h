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
#include "PrivateLedger.h"
#include "secure_allocator.h"

namespace acl
{
    //used by BL
    bool add_access_to_members(const secure::vector<secure::string> &addresses, const secure::vector<SignerPubKey> &keys, const uint16_t &svn, const secure::string& nonce);
    bool remove_access_from_member(const secure::vector<secure::string> &addresses, const SignerPubKey &key, const uint16_t &svn, const secure::string& nonce);
    Result acl_set_public(const StlAddress &addr);
    // bool create_group(const GroupID &g_id);
    bool add_members(const secure::vector<SignerPubKey> &keys, const uint16_t &svn, const secure::string& nonce);
    bool remove_members(const secure::vector<SignerPubKey> &keys, const uint16_t &svn, const secure::string& nonce);
    bool change_member_key(const SignerPubKey &old_key, const SignerPubKey &new_key, const uint16_t &svn, const secure::string& nonce);
    bool update_svn(const uint16_t &new_svn, const uint16_t &txn_svn, const secure::string& nonce);
} // namespace acl
