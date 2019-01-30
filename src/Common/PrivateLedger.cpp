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
#include <vector>
#include <algorithm>
#include <cstring>
#include "secure_allocator.h"
#ifdef SGX_ENCLAVE
#include "enclave_log.h"
#else
#include "app_log.h"
#endif

bool operator==(const StlAddress &lhs, const StlAddress &rhs)
{
	return lhs.val == rhs.val;
}

bool operator<(const StlAddress &lhs, const StlAddress &rhs)
{
	return lhs.val < rhs.val;
}

// utility function to provide copy conversion from vector of bytes
// to a stl hex string container.
constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
						   '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
secure::string ToHexString(const uint8_t *in, int len)
{
	secure::string out = "";
	out.reserve(2 * len);
	for (int i = 0; i < len; ++i)
	{
		out += hexmap[(in[i] & 0xF0) >> 4];
		out += hexmap[in[i] & 0x0F];
	}
	return out;
}

// utility function to provide copy conversion from stl string container
// to a vector of bytes.
secure::vector<uint8_t> ToHexVector(const secure::string &in)
{
	size_t str_size = in.size();
	for (size_t i = 0; i < str_size; i++)
	{
		if (!isxdigit(in[i]))
		{
			PRINT(ERROR, COMMON, "ToHexVector accepts only hex characters\n");
			PRINT(INFO, COMMON, "got %s, size %ld, index is %ld\n", in.c_str(), str_size, i);
			return secure::vector<uint8_t>();
		}
	}
	secure::vector<uint8_t> out;
	out.reserve(str_size / 2);
	for (size_t i = 0; i < str_size; i += 2)
	{
		out.push_back((uint8_t)(0xff & std::stoi(in.substr(i, 2).c_str(), nullptr, 16)));
	}
	return out;
}

std::pair<bool, SignerPubKey> getKeyFromStr(const secure::string &key_str)
{
	SignerPubKey key = {0};
	// validate key is only hex digits
	auto index = std::find_if(key_str.begin(), key_str.end(), [&](unsigned char c) { return !std::isxdigit(c); });
	if (index != key_str.end())
	{
		PRINT(ERROR, COMMON, "getKeyFromStr fail, got non hex charecters\n");
		PRINT(INFO, COMMON, "got %s\n", key_str.c_str());
		return std::make_pair(false, key);
	}
	//validate key and compress if needed
	if (key_str.size() == 2 * UNCOMPRESSED_PUB_KEY_BYTE_LENGTH)
	{
		// validate key starts with '04' and compreass key
		if (key_str.compare(0, 2, "04") != 0)
		{
			PRINT(ERROR, COMMON, "getKeyFromStr fail, public key must start with 04\n");
			return std::make_pair(false, key);
		}
		key_str.copy(key.data(), key.size() - 1);
		// prefix is 02 if 'Y' is even and 03 if odd instead of 04
		key[1] = (std::stoi(key_str.substr(key_str.size() - 1).c_str(), nullptr, 16) & 1) == 0 ? '2' : '3';
		key[key.size() - 1] = '\0';
		return std::make_pair(true, key);
	}
	else if (key_str.size() == 2 * PUB_KEY_BYTE_LENGTH)
	{
		// validate key starts with '02' or '03'
		if (key_str.compare(0, 2, "02") != 0 && key_str.compare(0, 2, "03") != 0)
		{
			PRINT(ERROR, COMMON, "getKeyFromStr fail, compressed public key must start with 02 or 03\n");
			return std::make_pair(false, key);
		}
		key_str.copy(key.data(), key.size() - 1);
		key[key.size() - 1] = '\0';
		return std::make_pair(true, key);
	}
	else
	{
		PRINT(ERROR, COMMON, "getKeyFromStr fail, length of public key must be 65 or 33\n");
		return std::make_pair(false, key);
	}
}

std::pair<bool, StlAddress> getAddressFromStr(const secure::string &addr_str)
{
	StlAddress addr;
	addr.val = {0};
	// validate addr_str is only hex digits
	auto index = std::find_if(addr_str.begin(), addr_str.end(), [&](unsigned char c) { return !std::isxdigit(c); });
	if (index != addr_str.end())
	{
		PRINT(ERROR, COMMON, "getAddressFromStr fail, got non hex charecters\n");
		PRINT(INFO, COMMON, "got %s\n", addr_str.c_str());
		return std::make_pair(false, addr);
	}
	//validate length
	if (addr_str.size() != ADDRESS_LENGTH - 1)
	{
		PRINT(ERROR, COMMON, "getAddressFromStr fail, bad string size\n");
		return std::make_pair(false, addr);
	}
	// copy string to char array
	addr_str.copy(addr.val.data(), ADDRESS_LENGTH - 1);
	addr.val[addr.val.size() - 1] = '\0';
	return std::make_pair(true, addr);
}
