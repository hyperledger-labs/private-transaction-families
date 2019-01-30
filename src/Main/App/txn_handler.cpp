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

// utility function to provide copy conversion from stl string container
// that contains hex as string, to a vector of bytes.
std::vector<uint8_t> ToHexVector(const std::string &in)
{
    unsigned int str_size = in.length();
    for (unsigned int i = 0; i < str_size; i++)
    {
        if (!isxdigit(in[i]))
        {
            PRINT(ERROR, LISTENER, "ToHexVector accepts only hex characters\n");
            return std::vector<uint8_t>();
        }
    }
    std::vector<uint8_t> out;
    out.reserve(str_size / 2);
    for (unsigned int i = 0; i < str_size; i += 2)
    {
        out.push_back(0xff & std::stoi(in.substr(i, 2), nullptr, 16));
    }
    return out;
}

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
    auto serialized_header = this->txn->header()->GetSerializedHeader();
    auto nonce = this->txn->header()->GetValue(sawtooth::TransactionHeaderField::TransactionHeaderNonce);
    auto pub_key = this->txn->header()->GetValue(sawtooth::TransactionHeaderField::TransactionHeaderSignerPublicKey);
    auto payload_hash = this->txn->header()->GetValue(sawtooth::TransactionHeaderField::TransactionHeaderPayloadSha512);
    auto signature = this->txn->signature();
    auto payload = this->txn->payload();
    
    std::vector<uint8_t> header_vec(serialized_header.begin(), serialized_header.end());
    std::vector<uint8_t> signature_vec = ToHexVector(signature);
    std::vector<uint8_t> payload_hash_vec = ToHexVector(payload_hash);
    std::vector<uint8_t> payload_vec(payload.begin(), payload.end());
    if (pub_key.size() != PUB_KEY_BYTE_LENGTH * 2 && pub_key.size() != UNCOMPRESSED_PUB_KEY_BYTE_LENGTH * 2)
    {
        throw sawtooth::InvalidTransaction(" signer public key size is not 33 or 67 bytes");
    }
    if (signature_vec.size() != 64)
    {
        throw sawtooth::InvalidTransaction(" signature size is not 64 bytes");
    }
    if (payload_hash_vec.size() != 64)
    {
        throw sawtooth::InvalidTransaction(" payload hash size is not 64 bytes");
    }
    sgx_status_t ret_val;
    if (SGX_SUCCESS != ecall_wrapper(secure_apply, eid, &ret_val,
                                     header_vec.data(),
                                     header_vec.size(),
                                     nonce.c_str(),
                                     pub_key.c_str(),
                                     signature_vec.data(),
                                     payload_hash_vec.data(),
                                     payload_vec.data(),
                                     payload_vec.size()) ||
        SGX_SUCCESS != ret_val)
    {
        std::string err_str(" Error while handling transaction, sgx error code is ");
        err_str.append(std::to_string(ret_val));
        throw sawtooth::InvalidTransaction(err_str);
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
