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

namespace business_logic
{
    bool execute_transaction(const secure::string &payload, const SignerPubKey &signerPubKey, const uint16_t &svn, const secure::string& nonce);
    bool bl_read(const StlAddress &addr, const SignerPubKey &key, secure::string *out_value, const uint16_t &svn);
} // namespace business_logic
