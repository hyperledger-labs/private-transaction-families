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

#include <string>
#include <mutex>
#include "sawtooth_sdk.h"

// TODO until RFC (https://github.com/hyperledger/sawtooth-rfcs/pull/23/) PR is merged, we cannot validate txn header inside SGX code
/* in order to test it, compile sawtooth cxx sdk and validator from the following and change the define to 1
*  Sawtooth-Core: https://github.com/arsulegai/sawtooth-core/tree/raw-header-tpreq (last 5 commits)
*  Sawtooth-SDK-CXX: https://github.com/arsulegai/sawtooth-sdk-cxx/tree/raw-txnheader (last 2 commits)
*/
#define rfc_23 0

namespace txn_handler
{

extern sawtooth::GlobalStateUPtr contextPtr;

// Handles the processing of a transactions.
class PrivateApplicator : public sawtooth::TransactionApplicator
{
  public:
	PrivateApplicator(sawtooth::TransactionUPtr txn, sawtooth::GlobalStateUPtr state);
	void Apply();
};

// Defines the private Handler to register with the transaction processor
// sets the versions and types of transactions that can be handled.
class PrivateHandler : public sawtooth::TransactionHandler
{
  public:
	PrivateHandler();
	~PrivateHandler();

	std::string transaction_family_name() const;

	std::list<std::string> versions() const;

	std::list<std::string> namespaces() const;

	sawtooth::TransactionApplicatorUPtr GetApplicator(
		sawtooth::TransactionUPtr txn,
		sawtooth::GlobalStateUPtr state);

  private:
	std::string namespacePrefix;
};
}
