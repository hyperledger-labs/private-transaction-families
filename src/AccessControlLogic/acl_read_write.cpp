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

#include <stdexcept> // std::invalid_argument
#include "acl_read_write.h"
#include "acl_internal.h"
#include "secure_allocator.h"
#include "Enclave_t.h"
#include "config.h"
#include "ledger_keys.h"

#ifdef SGX_ENCLAVE
#include "enclave_log.h"
#else
#include "app_log.h"
#endif

namespace acl
{

static InternalState &internalState = InternalState::Instance();

bool acl_read(const StlAddress &addr, const SignerPubKey &key, secure::vector<uint8_t> &out_value, const uint16_t &svn, bool is_client_reader)
{
	if (!has_access(addr, key, is_client_reader, svn))
	{
		PRINT(ERROR, ACL_LOG, "trying to read private address without permissions\n");
		PRINT(INFO, ACL_LOG, "address is %s, key is %s\n", addr.val.data(), key.data());
		return false;
	}
	return internalState.ReadFromAddress(addr, out_value, svn, is_client_reader);
}

bool acl_read_prefix(const secure::string &addr, const SignerPubKey &key, secure::vector<StlAddress> &out_values, const uint16_t &svn)
{
	if (!has_access(addr, key, false, svn))
	{
		PRINT(ERROR, ACL_LOG, "trying to read private address without permissions\n");
		PRINT(INFO, ACL_LOG, "address is %s, key is %s\n", addr.c_str(), key.data());
		return false;
	}
	return internalState.ReadFromAddressPrefix(addr, out_values);
}

Result acl_write(const StlAddress &addr, const SignerPubKey &key, const secure::vector<uint8_t> &buffer, const uint16_t &svn, const secure::string &nonce)
{

	if (!has_access(addr, key, false, svn))
	{
		PRINT(ERROR, ACL_LOG, "trying to write to private address without permissions\n");
		PRINT(INFO, ACL_LOG, "address is %s, key is %s\n", addr.val.data(), key.data());
		return ILLEGAL_ADDR;
	}
	return internalState.WriteToAddress(addr, buffer, key, svn, nonce);
}

bool acl_delete(const secure::vector<StlAddress> &addresses, const SignerPubKey &key, const uint16_t &svn)
{
	secure::string addresses_str = "";
	addresses_str.reserve(addresses.size() * ADDRESS_LENGTH);
	for (const auto &addr : addresses)
	{
		if (!has_access(addr, key, false, svn))
		{
			PRINT(ERROR, ACL_LOG, "trying to delete private address without permissions\n");
			PRINT(INFO, ACL_LOG, "address is %s, key is %s\n", addr.val.data(), key.data());
			return false;
		}
		// build addresses vec into one char array to be moved as C object
		addresses_str.append(addr.val.data());
	}
	sgx_status_t ret;
	tl_call_stl_delete(&ret, addresses_str.c_str(), addresses.size());
	if (ret == SGX_SUCCESS)
		return true;
	PRINT(ERROR, ACL_LOG, "delete from sawtooth failed\n")
	return false;
}

bool has_access(const secure::string &addr, const SignerPubKey &key, bool is_client_reader, const uint16_t &svn)
{
	// if public address return true
	if (internalState.IsAddressPublicPrefix(addr))
	{
		return true;
	}

	// if admin user return true
	// if (IsMemberInGroup(get_admin_grp(), m_id))
	if (key == get_admin_key())
	{
		return true;
	}

	if (internalState.CheckAccess(addr, key))
		return true;
	// if doesn't have access, check that ACL is in sync with merkle tree and retry
	if (!internalState.ReadAcl(svn, is_client_reader))
	{
		PRINT(ERROR, ACL_LOG, "read acl failed\n");
		return false;
	}
	return internalState.CheckAccess(addr, key);
}

bool has_access(const StlAddress &addr, const SignerPubKey &key, bool is_client_reader, const uint16_t &svn)
{
	return has_access(addr.val.data(), key, is_client_reader, svn);
}

bool acl_is_member(const SignerPubKey &key, const uint16_t &svn, bool sync_members)
{
	if (internalState.IsMember(key))
	{
		return true;
	}
	if (!sync_members)
	{
		return false;
	}
	// sync acl check again
	if (!internalState.ReadAcl(svn))
	{
		PRINT(ERROR, ACL_LOG, "sync members failed\n");
		return false;
	}
	return internalState.IsMember(key);
}

uint16_t get_cached_svn()
{
	return internalState.get_cached_svn();
}

bool update_cached_acl(const uint16_t &txn_svn, const bool &is_client_reader)
{
	// read acl svn address
	auto svn_addr = internalState.get_svn_addr();
	auto svn_ctx_data = secure::vector<uint8_t>();
	if (!internalState.ReadFromAddress(svn_addr, svn_ctx_data, txn_svn, is_client_reader))
	{
		PRINT(ERROR, ACL_LOG, "read svn from merkle tree retured false\n");
		return false;
	}
	// update svn
	size_t hash_size = 64;					  // hash is 64 bytes
	size_t svn_addr_min_size = 2 + hash_size; // 2 bytes for svn + hash
	if (svn_ctx_data.empty() || svn_ctx_data.size() < svn_addr_min_size)
	{
		// no svn entry in merkle tree
		PRINT(ERROR, ACL_LOG, "acl svn address in merkle tree is empty\n");
		return false;
	}
	// if we reached here than txn_svn >= ctx_svn used for svn_addr (otherwise read and decrypt address would fail)
	// get first two bytes for svn
	uint16_t ctx_svn = static_cast<uint16_t>((svn_ctx_data[1] << 8) + svn_ctx_data[0]);
	// get remaining bytes for hash
	svn_ctx_data.erase(std::begin(svn_ctx_data), std::begin(svn_ctx_data) + 2);
	// compare ctx svn to cached svn and ctx acl hash to cached acl hash
	if (ctx_svn == internalState.get_cached_svn() &&
		svn_ctx_data.size() == internalState.get_acl_hash().size() &&
		std::equal(std::begin(internalState.get_acl_hash()),
				   std::end(internalState.get_acl_hash()),
				   std::begin(svn_ctx_data)))
	{ // cached acl is allready up to date, nothing to update
		return true;
	}
	// cached acl doesn't match, update acl content
	// if we reached here txn_svn >= ctx_svn, use ctx_svn here to verify acl address is expected to be encrypted with svn that matches data in svn address
	return internalState.ReadAcl(ctx_svn, is_client_reader, svn_ctx_data);
}

const SignerPubKey get_admin_key()
{
	return internalState.get_admin_key();
}

} // namespace acl
