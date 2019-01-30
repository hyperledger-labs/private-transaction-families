#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "mock_tl.h"
#include "mock_ledger_keys.h"
#include "mock_crypto.h"
#include "mock_memset_s.h"

#include "acl_internal.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

using namespace acl;

static InternalState &state = InternalState::Instance();
Ledger_Keys_Manager ledger_keys_manager;
SignerPubKey key1, key2, key3;
StlAddress pub_addr, priv_addr1, priv_addr2;
// std::iota(std::begin(pub_addr.val), std::end(pub_addr.val), ';
void PrintKeys()
{
	std::cout << "3 keys are:\n"
			  << key1.data() << "\n"
			  << key2.data() << "\n"
			  << key3.data() << "\n";
}

void PrintAddresses()
{
	std::cout << "public address is:\n"
			  << pub_addr.val.data() << "\nprivate addresses are\n"
			  << priv_addr1.val.data() << "\n"
			  << priv_addr2.val.data() << "\n";
}

static void SetUpAcl()
{
	// setup keys
	std::array<uint8_t, UNCOMPRESSED_PUB_KEY_BYTE_LENGTH> long_key_bytes = {};
	std::array<uint8_t, PUB_KEY_BYTE_LENGTH> key_bytes = {};
	std::iota(std::begin(long_key_bytes), std::end(long_key_bytes), 4); // uncompressed key starts from 04
	key1 = getKeyFromStr(ToHexString(long_key_bytes.data(), long_key_bytes.size())).second;
	std::iota(std::begin(key_bytes), std::end(key_bytes), 2); // key starts from 02
	key2 = getKeyFromStr(ToHexString(key_bytes.data(), key_bytes.size())).second;
	std::iota(std::begin(key_bytes), std::end(key_bytes), 3); // key starts from 03
	key3 = getKeyFromStr(ToHexString(key_bytes.data(), key_bytes.size())).second;

	//setup addresses ADDRESS_LENGTH
	std::array<uint8_t, ADDRESS_LENGTH / 2> addr_bytes = {};
	std::iota(std::begin(addr_bytes), std::end(addr_bytes), 13);
	pub_addr = getAddressFromStr(ToHexString(addr_bytes.data(), addr_bytes.size())).second;
	std::iota(std::begin(addr_bytes), std::end(addr_bytes), 52);
	priv_addr1 = getAddressFromStr(ToHexString(addr_bytes.data(), addr_bytes.size())).second;
	std::iota(std::begin(addr_bytes), std::end(addr_bytes), 100);
	priv_addr2 = getAddressFromStr(ToHexString(addr_bytes.data(), addr_bytes.size())).second;

	PrintKeys();
	PrintAddresses();
}

static void TearDownAcl()
{
	deleteAllValues();
}

TEST(acl_internal, AddMember)
{
	ASSERT_EQ(state.AddMember(key1), SUCCESS);
	//add the same member twice should return ALREADY_EXISTS
	ASSERT_EQ(state.AddMember(key1), ALREADY_EXISTS);
}

TEST(acl_internal, IsMember)
{
	ASSERT_EQ(state.IsMember(key1), true);
	ASSERT_EQ(state.IsMember(key2), false);
	//admin is always a member
	ASSERT_EQ(state.IsMember(state.get_admin_key()), true);
}

TEST(acl_internal, RemoveMember)
{
	ASSERT_EQ(state.RemoveMember(key1), true);
	ASSERT_EQ(state.IsMember(key1), false);
	EXPECT_EQ(state.AddMember(key1), SUCCESS);
	ASSERT_EQ(state.IsMember(key1), true);
}

TEST(acl_internal, SetPublicAddress)
{
	ASSERT_EQ(state.IsAddressPublic(pub_addr), false);
	ASSERT_EQ(state.SetPublicAddress(pub_addr), SUCCESS);
	ASSERT_EQ(state.IsAddressPublic(pub_addr), true);
}

TEST(acl_internal, AllowAccess)
{
	//public address should not have request access
	ASSERT_EQ(state.AllowAccess(key1, pub_addr.val.data()), ILLEGAL_ADDR);

	//private address can be requested to have an access too
	EXPECT_EQ(state.IsAddressPublic(priv_addr1), false);
	ASSERT_EQ(state.AllowAccess(key1, priv_addr1.val.data()), SUCCESS);

	//private adress cannot be converted to public
	ASSERT_EQ(state.SetPublicAddress(priv_addr1), ILLEGAL_ADDR);

	//private adress cannot be shared for different users
	ASSERT_EQ(state.AllowAccess(key2, priv_addr1.val.data()), ILLEGAL_ADDR);

	//allow access will add member if not exist
	ASSERT_EQ(state.IsMember(key2), false);
	ASSERT_EQ(state.AllowAccess(key2, priv_addr2.val.data()), SUCCESS);
	ASSERT_EQ(state.IsMember(key2), true);
}

TEST(acl_internal, ChangeMemberKey)
{
	ASSERT_EQ(state.ChangeMemberKey(key1, key3), true);
	ASSERT_EQ(state.IsMember(key1), false);
	ASSERT_EQ(state.IsMember(key3), true);
	ASSERT_EQ(state.ChangeMemberKey(key3, key1), true);
}

TEST(acl_internal, CheckAccess)
{
	ASSERT_EQ(state.CheckAccess(priv_addr2.val.data(), key2), true);
	ASSERT_EQ(state.CheckAccess(priv_addr1.val.data(), key2), false);
	// check access for not existing member
	ASSERT_EQ(state.CheckAccess(pub_addr.val.data(), key3), false);
	// check access to public address
	ASSERT_EQ(state.CheckAccess(pub_addr.val.data(), key2), true);
}

TEST(acl_internal, WriteAcl)
{
	// checks serialize is working and svn + hash is written
	ASSERT_EQ(state.WriteAcl(1, "nonce"), true);
}

TEST(acl_internal, ClearAcl)
{
	state.ClearAcl();
	//check negative
	ASSERT_EQ(state.CheckAccess(priv_addr1.val.data(), key1), false);
	ASSERT_EQ(state.CheckAccess(pub_addr.val.data(), key1), false);
	ASSERT_EQ(state.IsMember(key1), false);
	ASSERT_EQ(state.IsMember(key2), false);
	ASSERT_EQ(state.IsMember(key3), false);
}

TEST(acl_internal, ReadAcl_bad_svn)
{
	ASSERT_EQ(state.ReadAcl(0), false);
	//check negative
	ASSERT_EQ(state.CheckAccess(priv_addr1.val.data(), key1), false);
	ASSERT_EQ(state.CheckAccess(pub_addr.val.data(), key1), false);
	ASSERT_EQ(state.IsMember(key1), false);
	ASSERT_EQ(state.IsMember(key2), false);
	ASSERT_EQ(state.IsMember(key3), false);
}

TEST(acl_internal, ReadAcl)
{
	ASSERT_EQ(state.ReadAcl(1), true);
	//check negative
	ASSERT_EQ(state.CheckAccess(priv_addr1.val.data(), key1), true);
	ASSERT_EQ(state.CheckAccess(pub_addr.val.data(), key1), true);
	ASSERT_EQ(state.IsMember(key1), true);
	ASSERT_EQ(state.IsMember(key2), true);
	ASSERT_EQ(state.IsMember(key3), false);
}

int main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	SetUpAcl();
	auto ret = RUN_ALL_TESTS();
	TearDownAcl();
	return ret;
}
