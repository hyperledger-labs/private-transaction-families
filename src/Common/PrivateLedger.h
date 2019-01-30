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
#include <vector>
#include <array>
#include <exception>
#include <utility>


typedef uint64_t Result;

#define SUCCESS 0x0000
#define OUT_OF_MEM 0x1000
#define ILLEGAL_ADDR 0x2000
#define ALREADY_EXISTS 0x3000
#define BAD_GROUP 0x4000
#define BAD_MEMBER 0x5000
#define BAD_PTR 0x6000
#define UNEXPECTED_ERR 0x7000

#define FAILED(X) ((X) != SUCCESS)

const int FAMILY_PREFIX = 6;
const int ADDRESS_LENGTH = 71; //70 hex characters + 1 for NULL terminator;

typedef union {
	std::array<char, ADDRESS_LENGTH> val;
	struct
	{
		std::array<char, FAMILY_PREFIX> family;
		std::array<char, 32> member_id;
		std::array<char, 32> posix;
		std::array<char, 1> null_terminator;
	} address_32_32;
	struct
	{
		std::array<char, FAMILY_PREFIX> family;
		std::array<char, 64> key;
		std::array<char, 1> null_terminator;
	} properties;
} StlAddress;

bool operator==(const StlAddress &lhs, const StlAddress &rhs);

bool operator<(const StlAddress &lhs, const StlAddress &rhs);

const int PUB_KEY_BYTE_LENGTH = 33; // 02 or 03 + 32 X bytes
const int UNCOMPRESSED_PUB_KEY_BYTE_LENGTH = 65; // 04 + 32 X bytes + 32 Y bytes
const int PUB_KEY_LENGTH = PUB_KEY_BYTE_LENGTH * 2 +1; //each byte is 2 chars in hex representation + 1 for NULL terminator

typedef std::array<char, PUB_KEY_LENGTH> SignerPubKey;

// typedef uint64_t GroupID;

// struct SignerGroupsPair
// {
// 	SignerPubKey key;
// 	std::vector<secure::string> groups_str;
// };

std::pair<bool, SignerPubKey> getKeyFromStr(const secure::string &key_str);

std::pair<bool, StlAddress> getAddressFromStr(const secure::string &addr_str);

// copy conversion from vector of bytes to a secure hex string container.
secure::string ToHexString(const uint8_t *in, int len);

// copy conversion from secure hex string to a vector of bytes.
secure::vector<uint8_t> ToHexVector(const secure::string &in);