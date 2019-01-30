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


#include "PrivateLedger.h"
#include "access_control.h"

namespace acl
{
extern "C"
{

bool acl_is_member(const SignerPubKey &PublicKey)
{
	(void)PublicKey;
	
	return true;
}

bool acl_has_access(const StlAddress &addr, const SignerPubKey &key, bool is_client_reader)
{
	(void)addr;
	(void)key;
	(void)is_client_reader;
	
	return true;
}

bool acl_read(const StlAddress &addr, const SignerPubKey &key, secure::string* out_value, bool is_client_reader)
{
	(void)addr;
	(void)key;
	(void)is_client_reader;
	
	*out_value = "fake response";
	return true;
}

} // extern "C"
} // namespace acl
