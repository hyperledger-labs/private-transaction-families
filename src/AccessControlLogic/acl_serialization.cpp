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

#include <algorithm>
#include <sstream>
#include "acl_internal.h"
#include "PrivateLedger.h"
#include "Enclave_t.h"
#ifdef SGX_ENCLAVE
#include "enclave_log.h"
#else
#include "app_log.h"
#endif
#include "config.h"

// convert uint64_t to uint8_t vector, returns {0} for n==0
secure::vector<uint8_t> to_byte_vec(uint64_t n, size_t padding_size = 1)
{
	secure::vector<uint8_t> ret = {};
	do
	{
		ret.push_back(n & 0xff);
		n = n >> 8;
		if (padding_size > 0)
			padding_size--;
	} while (n > 0 || padding_size > 0);
	return ret;
}

uint64_t from_byte_vec(const secure::vector<uint8_t>::const_iterator &iter, const uint8_t len)
{
	uint64_t res = 0;
	for (int i = len - 1; i >= 0; i--)
	{
		res = res << 8;
		res += *(iter + i);
	}
	return res;
}

namespace acl
{
// builds the acl intance from acl vector
// changes acl even when failed, if returns false clear acl by calling again with empty vec
bool InternalState::DeserializeAcl(const secure::vector<uint8_t> &acl_vec)
{
	//zero the existing AclMemberTable and public address vector
	acl_members = {};
	public_address_vec = {};
	admin_key = {};

	// if given empty string from sawtooth return empty acl with only admin access
	if (acl_vec.empty())
	{
		admin_key = config::get_admin_key();
		acl_members.emplace(admin_key, secure::vector<secure::string>());
		return true;
	}
	try
	{
		auto iter = std::begin(acl_vec);
		// fill public address vec
		auto counter = from_byte_vec(iter, 4);
		iter += 4;
		// get vector size
		for (uint64_t i = 0; i < counter; i++)
		{
			auto addr_str = ToHexString(&(*iter), (ADDRESS_LENGTH - 1) / 2); // length in byte is 1/2 of hex str len
			auto addr_res = getAddressFromStr(addr_str);
			if (!addr_res.first)
			{
				PRINT(INFO, ACL_LOG, "failure addr_str is %s\n", addr_str.c_str());
				return false;
			}
			public_address_vec.emplace_back(addr_res.second);
			iter += (ADDRESS_LENGTH - 1) / 2;
		}
		// add admin
		auto key_str = ToHexString(&(*iter), PUB_KEY_BYTE_LENGTH);
		auto admin_key_res = getKeyFromStr(key_str);
		if (!admin_key_res.first)
		{
			PRINT(INFO, ACL_LOG, "failing admin_key_res is %s\n", key_str.c_str());
			return false;
		}
		admin_key = admin_key_res.second;
		iter += PUB_KEY_BYTE_LENGTH;

		// fill AclMemberTable
		while (iter != std::end(acl_vec))
		{
			key_str = ToHexString(&(*iter), PUB_KEY_BYTE_LENGTH);
			auto key_res = getKeyFromStr(key_str);
			if (!key_res.first)
			{
				PRINT(ERROR, ACL_LOG, "failing key_res is %s\n", key_str.c_str());
				return false;
			}
			SignerPubKey signer = key_res.second;
			iter += PUB_KEY_BYTE_LENGTH;

			counter = *iter;
			iter += 1;
			auto num_of_addrs = from_byte_vec(iter, (counter & 0xff));
			iter += counter;
			secure::vector<secure::string> addr_vec;
			addr_vec.reserve(num_of_addrs);
			for (unsigned i = 0; i < num_of_addrs; i++)
			{
				counter = from_byte_vec(iter, 2);
				iter += 2;
				addr_vec.emplace_back(ToHexString(&(*iter), static_cast<int>(counter)));
				iter += counter;
			}
			auto ret = acl_members.emplace(signer, addr_vec);
			if (!ret.second)
				return false;
		}
		return true;
	}
	catch (...)
	{
		return false;
	}
}

//return ACL as vector to be written in merkle tree
const secure::vector<uint8_t> InternalState::SerializeAcl() const
{
	//Public addresses vector
	secure::vector<uint8_t> acl_vec = to_byte_vec(public_address_vec.size(), 4); // add public address vec length, assuming 4 hex digits are enough
	for (const auto &pub_addr_it : public_address_vec)
	{
		auto pub_addr_vec = ToHexVector(pub_addr_it.val.data());
		acl_vec.insert(std::end(acl_vec), std::begin(pub_addr_vec), std::end(pub_addr_vec)); // append addresses
	}

	// add admin
	// convert key from hex string to byte vector
	auto admin_key_vec = ToHexVector(admin_key.data());
	acl_vec.insert(std::end(acl_vec), std::begin(admin_key_vec), std::end(admin_key_vec)); // append admin key

	// AclMemberTable
	for (const auto &acl_it : acl_members)
	{
		auto key_vec = ToHexVector(acl_it.first.data());
		acl_vec.insert(std::end(acl_vec), std::begin(key_vec), std::end(key_vec)); // append member key
		auto temp_id = to_byte_vec(acl_it.second.size());						   // get vec length
		acl_vec.emplace_back(temp_id.size() & 0xff);							   // add size of vec length
		acl_vec.insert(std::end(acl_vec), std::begin(temp_id), std::end(temp_id)); // append vec length
		for (const auto &address : acl_it.second)
		{
			auto addr_vec = ToHexVector(address);
			temp_id = to_byte_vec(addr_vec.size(), 2);									 // address string length in two characters
			acl_vec.insert(std::end(acl_vec), std::begin(temp_id), std::end(temp_id));   // append address size
			acl_vec.insert(std::end(acl_vec), std::begin(addr_vec), std::end(addr_vec)); // append address
		}
	}
	return acl_vec;
}

} // namespace acl
