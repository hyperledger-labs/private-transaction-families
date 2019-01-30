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
#include <cstring>
#include <inttypes.h>
#include "acl_internal.h"
#include "data_records_crypto.h"
#include "PrivateLedger.h"
// #include "HashWrapper.h"
#include "Enclave_t.h"
#ifdef SGX_ENCLAVE
#include "enclave_log.h"
#else
#include "app_log.h"
#endif
#include "config.h"

namespace acl
{
InternalState &InternalState::Instance()
{
	static InternalState singletonInstance;
	return singletonInstance;
}

InternalState::InternalState()
{
	// add admin
	admin_key = config::get_admin_key();
	acl_members.emplace(admin_key, secure::vector<secure::string>());
}

InternalState::~InternalState()
{
}

bool InternalState::IsMember(const SignerPubKey &k) const
{
	if (acl_members.count(k) == 0)
	{
		return false;
	}
	return true;
}

Result InternalState::AddMember(const SignerPubKey &k)
{
	if (IsMember(k))
	{
		PRINT(ERROR, ACL_LOG, "add member failed\n");
		return ALREADY_EXISTS;
	}
	try
	{
		auto ret = acl_members.emplace(k, secure::vector<secure::string>());
		if (ret.second)
			return SUCCESS;
		PRINT(ERROR, ACL_LOG, "add member emplace error\n");
		return UNEXPECTED_ERR;
	}
	catch (...)
	{
		PRINT(ERROR, ACL_LOG, "add member unexpected error\n");
		return UNEXPECTED_ERR;
	}
}

bool InternalState::RemoveMember(const SignerPubKey &k)
{
	return (1 == acl_members.erase(k));
}

bool InternalState::ChangeMemberKey(const SignerPubKey &old_key, const SignerPubKey &new_key)
{
	auto it = acl_members.find(new_key);
	if (it != acl_members.end()) // new key allready exists
		return false;
	it = acl_members.find(old_key);
	if (it == acl_members.end()) // old key doesn't exists
		return false;
	std::swap(acl_members[new_key], it->second);
	// Erase old key from map
	acl_members.erase(it);

	// if admin changed his key, update amdin_key
	if (old_key == admin_key)
		admin_key = new_key;
	return true;
}

const SignerPubKey InternalState::get_admin_key() const
{
	return admin_key;
}

Result InternalState::SetPublicAddress(const StlAddress &addr)
{
	//if already used as private, don't allow to set as public
	secure::string addr_str(addr.val.begin(), addr.val.end());
	for (const auto &it : acl_members)
	{
		auto res = std::find_if(std::begin(it.second), std::end(it.second),
								[&](const secure::string &priv_addr) { return is_prefix(priv_addr, addr_str); });
		// found priv address that is prefix of requested public address
		if (res != std::end(it.second))
			return ILLEGAL_ADDR;
	}
	// if allready public, nothing to do
	if (!IsAddressPublic(addr))
	{
		public_address_vec.push_back(addr);
	}
	return SUCCESS;
}

// adding access to signer, add signer if not exists
Result InternalState::AllowAccess(const SignerPubKey &signer, const secure::string &addr)
{
	auto prefix_length = addr.size();
	if (prefix_length < FAMILY_PREFIX || prefix_length >= ADDRESS_LENGTH)
	{
		PRINT(ERROR, ACL_LOG, "allow access prefix length mut be between 6 and 70\n");
		return ILLEGAL_ADDR;
	}
	//if in public list should not have request access
	if (IsAddressPublicPrefix(addr))
	{
		PRINT(ERROR, ACL_LOG, "can't add access to address %s since it is allready public\n", addr.c_str());
		return ILLEGAL_ADDR;
	}

	// can't have overlap with other acl entry,
	// if address is prefix for existing address or the other way around, reject
	for (const auto &it : acl_members)
	{
		auto res = std::find_if(std::begin(it.second), std::end(it.second),
								[&](const secure::string &priv_addr) { return is_prefix(priv_addr, addr) || is_prefix(addr, priv_addr); });
		// found priv address that is prefix of requested public address
		if (res != std::end(it.second))
		{
			PRINT(ERROR, ACL_LOG, "can't add access to address %s since it collides with existing acl entry\n", addr.c_str());
			return ILLEGAL_ADDR;
		}
	}
	auto member_iter = acl_members.find(signer);
	// if member doesn't existadd key with new address
	if (member_iter == std::end(acl_members))
	{
		auto map_pair = acl_members.emplace(signer, secure::vector<secure::string>{addr});
		if (!map_pair.second)
			return UNEXPECTED_ERR;
	}
	else // if member exists append address (we allready know it doesn't collidde with existing address)
	{
		member_iter->second.emplace_back(addr);
	}
	return SUCCESS;
}

// remove address from signer list, won't change list if failed
Result InternalState::RemoveAccess(const SignerPubKey &signer, const secure::string &addr)
{
	auto prefix_length = addr.size();
	if (prefix_length < FAMILY_PREFIX || prefix_length >= ADDRESS_LENGTH)
	{
		PRINT(ERROR, ACL_LOG, "remove access prefix length mut be between 6 and 70\n");
		return ILLEGAL_ADDR;
	}

	auto acl_it = acl_members.find(signer);
	if (acl_it == acl_members.end())
	{
		PRINT(ERROR, ACL_LOG, "can't remove access to signer public key %s since it is not a member\n", signer.data());
		return ILLEGAL_ADDR;
	}
	auto remove_it = std::remove_if(std::begin(acl_it->second), std::end(acl_it->second),
									[&](const secure::string &existing_addr) { return existing_addr == addr; });
	//if nothing to be removed
	if (remove_it == std::end(acl_it->second))
	{
		PRINT(ERROR, ACL_LOG, "can't remove access since signer %s doesn't have access to address %s\n", signer.data(), addr.c_str());
		return ILLEGAL_ADDR;
	}

	acl_it->second.erase(remove_it, std::end(acl_it->second));
	return SUCCESS;
}

bool InternalState::WriteAcl(const uint16_t &svn, const secure::string &nonce)
{
	auto acl_vec = SerializeAcl();
	if (acl_vec.empty())
	{
		PRINT(ERROR, ACL_LOG, "get acl string failed\n")
		return false;
	}

	if (SUCCESS != WriteToAddress(get_acl_addr(), acl_vec, admin_key, svn, nonce))
	{
		PRINT(ERROR, ACL_LOG, "Write to acl address failed\n");
		return false;
	}
	// update acl hash and svn
	sha512_data_t hash_res = {};
	if (!sha512_msg(acl_vec.data(), acl_vec.size(), &hash_res))
	{
		PRINT(ERROR, ACL_LOG, "write acl failed to calculate acl hash\n");
		return false;
	}
	std::copy(std::begin(hash_res.data), std::end(hash_res.data), std::begin(acl_hash));
	secure::vector<uint8_t> new_svn_vec = {svn && 0xff, static_cast<uint8_t>(svn >> 8)}; //svn
	new_svn_vec.reserve(acl_hash.size() + 2);
	new_svn_vec.insert(std::end(new_svn_vec), std::begin(acl_hash), std::end(acl_hash)); // append acl hash
	// write new svn to svn address
	if (SUCCESS != WriteToAddress(get_svn_addr(), new_svn_vec, admin_key, svn, nonce))
	{
		PRINT(ERROR, ACL_LOG, "Write to svn address failed\n");
		return false;
	}
	cached_svn = svn;
	return true;
}

bool InternalState::ReadAcl(const uint16_t &svn, bool is_client_reader, const secure::vector<uint8_t> &ctx_acl_hash)
{
	secure::vector<uint8_t> acl_vec = {};
	if (!ReadFromAddress(get_acl_addr(), acl_vec, svn, is_client_reader))
		return false;

	// check expected hash before deserializing
	sha512_data_t hash_res = {};
	if (!sha512_msg(acl_vec.data(), acl_vec.size(), &hash_res))
	{
		PRINT(ERROR, ACL_LOG, "read acl failed to calculate acl hash\n");
		return false;
	}
	std::array<uint8_t, 64> new_cashed_acl_hash;
	std::copy(std::begin(hash_res.data), std::end(hash_res.data), std::begin(new_cashed_acl_hash));

	if (!ctx_acl_hash.empty() &&
		(ctx_acl_hash.size() != new_cashed_acl_hash.size() ||
		 !std::equal(std::begin(new_cashed_acl_hash),
					 std::end(new_cashed_acl_hash),
					 std::begin(ctx_acl_hash))))
	{
		// error: hash doesn't match hash from svn address
		PRINT(ERROR, ACL_LOG, "acl hash doesn't match expected hash\n");
		return false;
	}
	// if existing hash matches hash from ctx, nothing to update
	if (acl_hash == new_cashed_acl_hash)
	{
		return true;
	}
	// update acl
	if (DeserializeAcl(acl_vec))
	{
		cached_svn = svn;
		acl_hash = new_cashed_acl_hash;
		return true;
	}
	else // reset acl on failure since not sure what DeserializeAcl changed before failing
	{
		PRINT(ERROR, ACL_LOG, "DeserializeAcl failed, clearing acl data\n");
		DeserializeAcl(secure::vector<uint8_t>());
		cached_svn = 0;
		acl_hash = {};
		return false;
	}
}

bool InternalState::CheckAccess(const secure::string &addr, const SignerPubKey &signer) const
{
	auto acl_it = acl_members.find(signer);
	if (acl_it == acl_members.end())
	{
		return false;
	}
	if (IsAddressPublicPrefix(addr))
	{
		return true;
	}
	auto res = std::find_if(std::begin(acl_it->second), std::end(acl_it->second),
							[&](const secure::string &existing_addr) { return is_prefix(existing_addr, addr); });
	return res != std::end(acl_it->second);
}

bool InternalState::ReadFromAddressPrefix(const secure::string &addr, secure::vector<StlAddress> &out_values) const
{
	std::vector<char> value = {};
	int ret;
	uint32_t id;
	tl_call_stl_read_prefix(&ret, &id, addr.c_str(), value.data(), 0);
	if (ret == -1)
	{
		PRINT(ERROR, ACL_LOG, "read from sawtooth by prefix failure, couldn't get data size\n");
		return false;
	}
	if (ret == 0)
	{
		out_values = secure::vector<StlAddress>();
		return true;
	}
	uint32_t data_size = ret;
	value.reserve(data_size * ADDRESS_LENGTH);
	tl_call_stl_read_prefix(&ret, &id, addr.c_str(), value.data(), data_size);
	if (ret == 0)
	{
		out_values = secure::vector<StlAddress>();
		return true;
	}
	if (ret < 0)
	{
		PRINT(ERROR, ACL_LOG, "read from sawtooth by prefix failure\n");
		return false;
	}
	const int add_len = ADDRESS_LENGTH-1;
	for (int i = 0; i < ret; i++)
	{
		auto res  = getAddressFromStr(secure::string(std::begin(value) + (add_len*i),
													 std::begin(value) + ((i+1)*add_len)));
		if (!res.first)
		{
			PRINT(ERROR, ACL_LOG, "read address prefix failure, can't convert string to address\n");
			return false;
		}
		out_values.emplace_back(res.second);
	}
	return true;
}

bool InternalState::ReadFromAddress(const StlAddress &addr, secure::vector<uint8_t> &out_value, const uint16_t &svn, bool is_client_reader) const
{
	std::vector<char> value = {};
	int ret;
	uint32_t id;
	if (is_client_reader)
		tl_call_stl_read_cr(&ret, &id, addr.val.data(), value.data(), 0);
	else
		tl_call_stl_read(&ret, &id, addr.val.data(), value.data(), 0);
	if (ret == -1)
	{
		PRINT(ERROR, ACL_LOG, "read from sawtooth failure, couldn't get data size\n");
		return false;
	}
	if (ret == 0)
	{
		out_value = secure::vector<uint8_t>();
		return true;
	}
	uint32_t data_size = ret;
	value.reserve(data_size + 1);
	if (is_client_reader)
		tl_call_stl_read_cr(&ret, &id, addr.val.data(), value.data(), data_size);
	else
		tl_call_stl_read(&ret, &id, addr.val.data(), value.data(), data_size);
	if (ret == 0)
	{
		out_value = secure::vector<uint8_t>();
		return true;
	}
	if (ret > 0)
	{
		out_value = ToHexVector(secure::string(std::begin(value), std::begin(value) + ret));
		if (!IsAddressPublic(addr))
		{
			// decrypt using crypto lib
			secure::vector<uint8_t> decrypted_data = {};
			if (!DecryptAddrData(out_value, addr, svn, decrypted_data))
			{
				PRINT(ERROR, ACL_LOG, "decrypt data from sawtooth failure\n");

				return false;
			}
			out_value = decrypted_data;
		}
		return true;
	}
	PRINT(ERROR, ACL_LOG, "read from sawtooth failure\n");
	return false;
}

Result InternalState::WriteToAddress(const StlAddress &addr, const secure::vector<uint8_t> &data, const SignerPubKey &signer, const uint16_t &svn, const secure::string &nonce) const
{
	secure::string encrypted_data;
	if (!IsAddressPublic(addr))
	{
		// encrypt using crypto lib
		if (!EncryptAddrData(data, addr, signer, svn, nonce, encrypted_data))
		{
			PRINT(ERROR, ACL_LOG, "EncryptAddrData failed\n");
			return UNEXPECTED_ERR;
		}
	}
	else
	{
		encrypted_data = ToHexString(data.data(), static_cast<int>(data.size()));
	}

	sgx_status_t ret;
	tl_call_stl_write(&ret, addr.val.data(), encrypted_data.c_str(), encrypted_data.length());
	if (ret == SGX_SUCCESS)
		return SUCCESS;
	PRINT(ERROR, ACL_LOG, "write to sawtooth failed\n");
	return UNEXPECTED_ERR;
}

bool InternalState::IsAddressPublicPrefix(const secure::string &addr) const
{
	// requested address is an input of existing  public address
	auto res = std::find_if(std::begin(public_address_vec), std::end(public_address_vec),
							[&](const StlAddress &existing_addr) { return is_prefix(addr, existing_addr.val.data()); });
	return res != std::end(public_address_vec);
}

bool InternalState::IsAddressPublic(const StlAddress &addr) const
{
	if (std::find(std::begin(public_address_vec), std::end(public_address_vec), addr) != public_address_vec.end())
	{
		return true;
	}
	return false;
}

//return true if A is prefix of B
bool InternalState::is_prefix(const secure::string &a_str, const secure::string &b_str) const
{
	auto pos = b_str.find(a_str);
	return (pos == 0);
}

StlAddress InternalState::get_acl_addr() const
{
	static const std::string ACL_ADDR_STR = config::get_prefix() + "0000000000000000000000000000000000000000000000000000000000000001";
	return getAddressFromStr(ACL_ADDR_STR.c_str()).second;
}

StlAddress InternalState::get_svn_addr() const
{
	static const std::string SVN_ADDR_STR = config::get_prefix() + "0000000000000000000000000000000000000000000000000000000000000002";
	return getAddressFromStr(SVN_ADDR_STR.c_str()).second;
}

std::array<uint8_t, 64> InternalState::get_acl_hash() const
{
	return acl_hash;
}

uint16_t InternalState::get_cached_svn() const
{
	return cached_svn;
}

bool InternalState::EncryptAddrData(const secure::vector<uint8_t> &toEncrypt, const StlAddress &addr, const SignerPubKey &signer, const uint16_t &svn, const secure::string &nonce, secure::string &out) const
{
	// if address key contains only zeroes except for last char - this is ACL address
	e_record_type type;
	if (std::all_of(std::begin(addr.properties.key), std::end(addr.properties.key) - 1, [](char c) { return c == '0'; }))
	{
		type = e_record_type::ACL_TYPE;
	}
	else
	{
		type = e_record_type::DATA_TYPE;
	}
	ledger_hex_address_t hex_addr;
	safe_memcpy(hex_addr, sizeof(ledger_hex_address_t), addr.val.data(), addr.val.size());

	public_ec_key_str_t signer_hex;
	safe_memcpy(signer_hex, sizeof(public_ec_key_str_t), signer.data(), signer.size());
	uint8_t *encrypted_data;
	uint32_t encrypted_data_size;

	if (!data_record_encrypt(type, svn, &signer_hex, nonce.c_str(), &hex_addr,
							 toEncrypt.data(), static_cast<uint32_t>(toEncrypt.size()),
							 &encrypted_data, &encrypted_data_size))
	{
		PRINT(ERROR, ACL_LOG, "data_record_encrypt failed\n");
		return false;
	}
	out = ToHexString(encrypted_data, encrypted_data_size);
	// free encrypted_data
	free(encrypted_data);
	return true;
}

bool InternalState::DecryptAddrData(const secure::vector<uint8_t> &toDecrypt, const StlAddress &addr, const uint16_t &svn, secure::vector<uint8_t> &out) const
{
	uint8_t *plain_data;
	// convert to uint8_t and back
	ledger_hex_address_t hex_addr;
	safe_memcpy(hex_addr, sizeof(ledger_hex_address_t), addr.val.data(), addr.val.size());
	uint32_t plain_data_len = 0;

	if (!data_record_decrypt(toDecrypt.data(), (uint32_t)toDecrypt.size(),
							 svn, &hex_addr, &plain_data, &plain_data_len))
	{
		PRINT(ERROR, ACL_LOG, "data_record_decrypt failed\n");
		return false;
	}

	out = secure::vector<uint8_t>(plain_data, plain_data + plain_data_len);
	// free plain data
	free(plain_data);
	return true;
}

void InternalState::ClearAcl()
{
	DeserializeAcl(secure::vector<uint8_t>()); // clear acl
	cached_svn = 0;
	acl_hash = {};
}

} // namespace acl
