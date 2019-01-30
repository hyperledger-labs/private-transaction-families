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
bool payloadToParams(const secure::string &payload, secure::string &verb, secure::string &name, int &value, int &addr_len);
StlAddress getAddress(const secure::string &name, const SignerPubKey &signerPubKey);
// Handle an IntKey 'set' verb action. This sets a IntKey value to
// the given value.
bool DoSet(const secure::string &name, const int value, const int addr_len, const SignerPubKey &signerPubKey, const uint16_t &svn, const secure::string& nonce);
// Handle an IntKey 'inc' and 'dec' verb action. This increments an IntKey value
// stored in global state by a given value.
bool DoIncDec(const secure::string &name, const int value, const SignerPubKey &signerPubKey, const uint16_t &svn, const secure::string& nonce);
}