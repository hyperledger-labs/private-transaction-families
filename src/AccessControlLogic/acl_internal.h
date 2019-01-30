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
#include <unordered_map>
#include <map>
#include <queue>
#include "PrivateLedger.h"
#include "secure_allocator.h"
#include "config.h"

namespace acl
{
// use ordered map to keep order after serialization
using AclMemberTable = std::map<SignerPubKey, secure::vector<secure::string>>;
//singleton class used for ACL implemetation
// TODO singleton is not the best option here, don't use it
class InternalState final
{
  public:
	InternalState(InternalState const &) = delete;			  // Copy construct
	InternalState(InternalState &&) = delete;				  // Move construct
	InternalState &operator=(InternalState const &) = delete; // Copy assign
	InternalState &operator=(InternalState &&) = delete;	  // Move assign
	static InternalState &Instance();

	// gropus
	// GroupID StringToGroupID(const secure::string &) const;
	// Result CreateNewGroup(const GroupID &);
	// Result AddMemberToGroup(GroupID, const MemberID &);
	// bool IsMemberInGroup(const GroupID &, const MemberID &) const;

	//access control
	Result SetPublicAddress(const StlAddress &);
	bool IsAddressPublic(const StlAddress &) const;
	bool IsAddressPublicPrefix(const secure::string &) const;
	Result AllowAccess(const SignerPubKey &signer, const secure::string &addr);
	Result RemoveAccess(const SignerPubKey &signer, const secure::string &addr);
	bool CheckAccess(const secure::string &addr, const SignerPubKey &signer) const;
	bool WriteAcl(const uint16_t &svn, const secure::string &nonce);
	bool ReadAcl(const uint16_t &svn, bool is_client_reader = false, const secure::vector<uint8_t> &acl_hash = {});
	void ClearAcl();

	// members
	// MemberID KeyToMemberID(const SignerPubKey &);
	bool IsMember(const SignerPubKey &) const;
	Result AddMember(const SignerPubKey &);
	bool RemoveMember(const SignerPubKey &k);
	bool ChangeMemberKey(const SignerPubKey &old_key, const SignerPubKey &new_key);
	const SignerPubKey get_admin_key() const;
	// bool update_members(const uint16_t &svn, const secure::string &nonce);
	// bool read_members(const uint16_t &svn);
	bool ReadFromAddress(const StlAddress &, secure::vector<uint8_t> &out_value, const uint16_t &svn, bool is_client_reader = false) const;
	bool ReadFromAddressPrefix(const secure::string &addr, secure::vector<StlAddress> &out_values) const;

	Result WriteToAddress(const StlAddress &, const secure::vector<uint8_t> &, const SignerPubKey &, const uint16_t &svn, const secure::string &nonce) const;
	//svn
	uint16_t get_cached_svn() const;
	std::array<uint8_t, 64> get_acl_hash() const;
	StlAddress get_svn_addr() const;

  private:
	InternalState();
	~InternalState();
	//acl
	bool is_prefix(const secure::string &a_str, const secure::string &b_str) const;
	//serialization
	bool DeserializeAcl(const secure::vector<uint8_t> &acl_str);
	const secure::vector<uint8_t> SerializeAcl() const;
	// groups
	// GroupsList Groups;
	AclMemberTable acl_members;
	SignerPubKey admin_key = {};
	std::vector<StlAddress> public_address_vec;
	StlAddress get_acl_addr() const;

	//encryption
	bool EncryptAddrData(const secure::vector<uint8_t> &toEncrypt, const StlAddress &addr, const SignerPubKey &signer, const uint16_t &svn, const secure::string &nonce, secure::string &out) const;
	bool DecryptAddrData(const secure::vector<uint8_t> &toDecrypt, const StlAddress &addr, const uint16_t &svn, secure::vector<uint8_t> &out) const;

	//SVN
	std::array<uint8_t, 64> acl_hash = {};
	uint16_t cached_svn = 0;
};
} // namespace acl
