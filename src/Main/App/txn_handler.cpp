/* Copyright 2018 Intel Corporation

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
------------------------------------------------------------------------------*/

#include <ctype.h>
#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include "../build/proto/transaction.pb.h"
#include "exceptions.h"
#include "txn_handler.h"
#include "config.h"
#include "PrivateLedger.h"
#ifdef SGX_ENCLAVE
#include "enclave_log.h"
#else
#include "app_log.h"
#endif
#include "Enclave_u.h"
#include "ecall_wrapper.h"
extern sgx_enclave_id_t eid;
namespace txn_handler
{

sawtooth::GlobalStateUPtr contextPtr;

//---------------------------------------------------------
// PrivateApplicator
//---------------------------------------------------------

PrivateApplicator::PrivateApplicator(sawtooth::TransactionUPtr txn,
                                     sawtooth::GlobalStateUPtr state) : TransactionApplicator(std::move(txn), std::move(state)) {}

void PrivateApplicator::Apply()
{
    PRINT(INFO, LISTENER, "PrivateApplicator::Apply started\n");
    //set current context
    contextPtr = std::move(this->state);

    // get transaction details
    auto serialized_header = this->txn->header_bytes();
    // parse header
    TransactionHeader txn_header;
    if (!txn_header.ParseFromString(serialized_header))
    {
        throw sawtooth::InvalidTransaction("failed to parse txn header bytes");
    }
    auto nonce = txn_header.nonce();
    auto pub_key = txn_header.signer_public_key();
    auto payload_hash = txn_header.payload_sha512();
    auto signature = this->txn->signature();
    auto payload = this->txn->payload();
    
    std::vector<uint8_t> header_vec(serialized_header.begin(), serialized_header.end());
    // std::vector<uint8_t> signature_vec = ToHexVector(signature);
    // std::vector<uint8_t> payload_hash_vec = ToHexVector(payload_hash);
    std::vector<uint8_t> payload_vec(payload.begin(), payload.end());
    if (pub_key.size() != PUB_KEY_BYTE_LENGTH * 2 && pub_key.size() != UNCOMPRESSED_PUB_KEY_BYTE_LENGTH * 2)
    {
        throw sawtooth::InvalidTransaction(" signer public key size is not 33 or 67 bytes");
    }
    if (signature.size() != 128)
    {
        throw sawtooth::InvalidTransaction(" signature size is not 64 bytes");
    }
    if (payload_hash.size() != 128)
    {
        throw sawtooth::InvalidTransaction(" payload hash size is not 64 bytes");
    }
    sgx_status_t ret_val;
    char err [MAX_ERROR_MSG_LEN+1];
    if (SGX_SUCCESS != ecall_wrapper(secure_apply, eid, &ret_val,
                                     header_vec.data(),
                                     header_vec.size(),
                                     nonce.c_str(),
                                     pub_key.c_str(),
                                     signature.c_str(),
                                     payload_hash.c_str(),
                                     payload_vec.data(),
                                     payload_vec.size(),
                                     err) ||
        SGX_SUCCESS != ret_val)
    {
        std::string err_msg("sgx error code is: ");
        err_msg.append(std::to_string(ret_val)).append(", error message is: ").append(err);
        throw sawtooth::InvalidTransaction(err_msg);
    }
    PRINT(INFO, LISTENER, "PrivateApplicator::Apply completed\n");
}

//---------------------------------------------------------
// PrivateHandler
//---------------------------------------------------------
PrivateHandler::PrivateHandler() : namespacePrefix(config::get_prefix()) {}

PrivateHandler::~PrivateHandler()
{
}

std::string PrivateHandler::transaction_family_name() const
{
    return config::get_namespace();
}

std::list<std::string> PrivateHandler::versions() const
{
    return {config::get_version()};
}

std::list<std::string> PrivateHandler::namespaces() const
{
    return {namespacePrefix};
}

sawtooth::TransactionApplicatorUPtr PrivateHandler::GetApplicator(
    sawtooth::TransactionUPtr txn,
    sawtooth::GlobalStateUPtr state)
{
    return sawtooth::TransactionApplicatorUPtr(
        new PrivateApplicator(std::move(txn), std::move(state)));
}
} // namespace txn_handler
