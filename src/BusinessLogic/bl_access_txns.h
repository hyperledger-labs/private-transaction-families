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
#include "secure_allocator.h"
#include "PrivateLedger.h"
#include "config.h"
namespace business_logic
{
    // checks if this is a special transaction to add/remove member/group from access control layer
    bool is_acl_txn(const secure::string &payload);
    bool do_acl_action(const secure::string &payload, const SignerPubKey &signerPubKey, const uint16_t &svn, const secure::string& nonce);
    config::ActionType get_acl_action(const secure::string &payload);
    bool extract_params(const secure::string &payload,
                        secure::string &action,
                        secure::string &key,
                        secure::string &address,
                        secure::string &group,
                        uint16_t &svn);
} // namespace business_logic