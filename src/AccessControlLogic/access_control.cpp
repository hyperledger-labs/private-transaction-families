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

#include <sstream>
#include <exception>
#include <algorithm>
#include "access_control.h"
#include "acl_internal.h"
#include "acl_read_write.h"
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

//TODO allow access to group and not just member
bool add_access_to_members(const secure::vector<secure::string> &addresses, const secure::vector<SignerPubKey> &keys, const uint16_t &svn, const secure::string &nonce)
{
	if (!(keys.size() == 1 || keys.size() == addresses.size()))
	{
		PRINT(ERROR, ACL_LOG, "add_access_to_members wrong input length, keys size %zu, addresses size %zu\n", keys.size(), addresses.size());
		return false;
	}
	// before making changes sync acl instance from merkle tree
	if (!internalState.ReadAcl(svn))
	{
		PRINT(ERROR, ACL_LOG, "read_acl failed\n");
		return false;
	}

	// add members access
	for (unsigned int i = 0; i < addresses.size(); i++)
	{
		// either add many addresses to one key or one address per key
		SignerPubKey key = keys.size() == 1 ? keys.front() : keys.at(i);

		// add access
		auto res = internalState.AllowAccess(key, addresses.at(i));
		if (res != SUCCESS)
		{
			PRINT(ERROR, ACL_LOG, "AllowAccess returned failure code: %lu\n", res);
			if (!internalState.ReadAcl(svn)) // resync acl in case something changed
			{
				PRINT(ERROR, ACL_LOG, "read_acl failed\n");
			}
			return false;
		}
	}

	// write back to merkle tree
	return internalState.WriteAcl(svn, nonce);
}

bool remove_access_from_member(const secure::vector<secure::string> &addresses, const SignerPubKey &key, const uint16_t &svn, const secure::string &nonce)
{
	// before making changes sync acl instance from merkle tree
	if (!internalState.ReadAcl(svn))
	{
		PRINT(ERROR, ACL_LOG, "read_acl failed\n");
		return false;
	}

	for (const auto &addr_str : addresses)
	{
		// remove access
		auto res = internalState.RemoveAccess(key, addr_str);
		if (res != SUCCESS)
		{
			PRINT(ERROR, ACL_LOG, "RemoveAccess returned failure code: %lu\n", res);
			if (!internalState.ReadAcl(svn)) // resync acl in case something changed
			{
				PRINT(ERROR, ACL_LOG, "read_acl failed\n");
			}
			return false;
		}
	}
	// write back to merkle tree
	return internalState.WriteAcl(svn, nonce);
}

Result acl_set_public(const StlAddress &addr)
{
	return internalState.SetPublicAddress(addr);
}

bool add_members(const secure::vector<SignerPubKey> &keys, const uint16_t &svn, const secure::string &nonce)
{
	// before making changes sync members instance from merkle tree
	if (!internalState.ReadAcl(svn))
	{
		PRINT(ERROR, ACL_LOG, "ReadAcl failed\n");
		return false;
	}

	// add members
	for (const auto &k : keys)
	{
		auto res = internalState.AddMember(k);
		if (res != SUCCESS)
		{
			PRINT(ERROR, ACL_LOG, "AddMember returned failure code: %lu\n", res);
			if (!internalState.ReadAcl(svn))
			{
				PRINT(ERROR, ACL_LOG, "ReadAcl failed\n");
			}
			return false;
		}
	}
	// write back to merkle tree
	return internalState.WriteAcl(svn, nonce);
}

bool remove_members(const secure::vector<SignerPubKey> &keys, const uint16_t &svn, const secure::string &nonce)
{
	// before making changes sync members instance from merkle tree
	if (!internalState.ReadAcl(svn))
	{
		PRINT(ERROR, ACL_LOG, "ReadAcl failed\n");
		return false;
	}

	// add members
	for (const auto &k : keys)
	{
		if (!internalState.RemoveMember(k))
		{
			PRINT(ERROR, ACL_LOG, "RemoveMember returned false\n");
			if (!internalState.ReadAcl(svn)) // resync acl in case something changed
			{
				PRINT(ERROR, ACL_LOG, "ReadAcl failed\n");
			}
			return false;
		}
	}
	// write back to merkle tree
	return internalState.WriteAcl(svn, nonce);
}

bool change_member_key(const SignerPubKey &old_key, const SignerPubKey &new_key, const uint16_t &svn, const secure::string &nonce)
{
	// before making changes sync members instance from merkle tree
	if (!internalState.ReadAcl(svn))
	{
		PRINT(ERROR, ACL_LOG, "ReadAcl failed\n");
		return false;
	}

	// remove old member
	if (!internalState.ChangeMemberKey(old_key, new_key))
	{
		PRINT(ERROR, ACL_LOG, "ChangeMemberKey returned false\n");
		if (!internalState.ReadAcl(svn))
		{
			PRINT(ERROR, ACL_LOG, "ReadAcl failed\n");
		}
		return false;
	}

	// write back to merkle tree
	return internalState.WriteAcl(svn, nonce);
}

bool update_svn(const uint16_t &new_svn, const uint16_t &txn_svn, const secure::string &nonce)
{
	// new suggested svn must bigger than txn svn (in this stage txn svn equals cached/ctx svn)
	// if both svns are 0 it might be first txn ever, don't reject
	if (!(new_svn == 0 && txn_svn == 0) && txn_svn >= new_svn)
	{
		PRINT(ERROR, ACL_LOG, "new svn must be bigger than existing svn\n");
		return false;
	}
	// new suggested svn can't be higher than encalve svn
	if (ledger_keys_manager.keys_ready() == false)
	{
		PRINT(ERROR, ACL_LOG, "failed to initialize keys\n");
		return SGX_ERROR_BUSY;
	}
	if (ledger_keys_manager.get_svn() < new_svn)
	{
		PRINT(ERROR, ACL_LOG, "new svn can't be bigger than TP svn\n");
		return false;
	}

	// reset acl
	internalState.ClearAcl();

	// write back empty acl to merkle tree with new svn
	return internalState.WriteAcl(new_svn, nonce);
}

} // namespace acl