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

#include "config.h"

namespace config
{
std::string get_namespace()
{
    //static const std::string TP_NAMESPACE = "tase_bsl";
    static const std::string TP_NAMESPACE = "private_intkey";
    return TP_NAMESPACE;
}
std::string get_version()
{
    static const std::string TP_VERSION = "1.0";
    return TP_VERSION;
}
std::string get_prefix()
{
    //static const std::string TP_PREFIX = "aabbcc";
    static const std::string TP_PREFIX = "bb563a";
    return TP_PREFIX;
}

// project admin public key
//TODO change based on admin's public key per project
SignerPubKey get_admin_key()
{
    static const SignerPubKey ADMIN_PUBLIC_KEY = {"026e3a6b2f0e66ac22af41b6759ab886458d11595f19280b0458e4decb2148d215"};
    return ADMIN_PUBLIC_KEY;
}

} // namespace config
