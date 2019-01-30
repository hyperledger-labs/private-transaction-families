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
#include "config.h"

namespace acl
{
//read from sawtooth,
bool acl_read(const StlAddress &addr, const SignerPubKey &key, secure::vector<uint8_t> &out_value, const uint16_t &svn, bool is_client_reader = false);
bool acl_read_prefix(const secure::string &addr, const SignerPubKey &key, secure::vector<StlAddress> &out_values, const uint16_t &svn);
Result acl_write(const StlAddress &addr, const SignerPubKey &key, const secure::vector<uint8_t> &buffer, const uint16_t &svn, const secure::string &nonce);
bool acl_delete(const secure::vector<StlAddress> & addresses, const SignerPubKey &key, const uint16_t &svn);
bool has_access(const StlAddress &addr, const SignerPubKey &key, bool is_client_reader, const uint16_t &svn);
bool has_access(const secure::string &addr, const SignerPubKey &key, bool is_client_reader, const uint16_t &svn);
//extern "C" because this is used by crypto lib which is written in C
extern "C" bool acl_is_member(const SignerPubKey &PublicKey, const uint16_t &svn = 0, bool sync_members = false);
bool update_cached_acl(const uint16_t &svn, const bool &is_client_reader);
uint16_t get_cached_svn();
const SignerPubKey get_admin_key();

} // namespace acl
