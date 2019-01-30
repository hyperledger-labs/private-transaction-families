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

#include <unordered_map>
#include <map>
#include <vector>
#include <queue>
#include <sstream>
#include <exception>
#include <mutex>
#include <inttypes.h>

#include "secure_allocator.h"
#include "Enclave_t.h"
#include "PrivateLedger.h"
#include "crypto.h"
#include "crypto_enclave.h"
#include "enclave_log.h"
#include "acl_read_write.h"
#include "businessLogic.h"
#include "crypto_ledger_reader_writer.h"
#include "ledger_keys.h"
#include "enclave_role.h"

sgx_status_t decrypt_payload(const char *data, secure::string &out_payload, const uint16_t &txn_svn)
{
    secure_data_content_t *p_request_data = NULL;
    // public_ec_key_str_t client_pub_key_str = {0};
    Ledger_Reader_Writer reader;
    size_t data_size = 0;
    if (ledger_keys_manager.keys_ready() == false)
    {
        PRINT(ERROR, LISTENER, "failed to initialize keys\n");
        return SGX_ERROR_BUSY;
    }

    // put in the current ledger svn, not the request svn
    reader.set_svn(ledger_keys_manager.get_svn());

    // set the keys to the ones corresponding to the request svn, otherwise the calculated key would be wrong
    if (reader.set_data_keys(&(ledger_keys_manager.get_ledger_keys_by_svn(txn_svn)->data_pub_ec_key_str),
							 &(ledger_keys_manager.get_ledger_keys_by_svn(txn_svn)->data_priv_ec_key_str)) == false)
    {
        PRINT(ERROR, LISTENER, "set_data_keys failed\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (reader.decode_secure_data(data, &p_request_data, &data_size, NULL) == false)
    {
        PRINT(ERROR, LISTENER, "decode_secure_data failed\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    //TODO how to check if we get uint8_t or string?
    secure::string decrypted_payload(p_request_data->data, p_request_data->data + data_size - sizeof(secure_data_content_t));

    if (p_request_data != NULL) // allocated in reader.decode_secure_data
    {
        free(p_request_data);
        p_request_data = NULL;
    }
    out_payload = decrypted_payload;
    return SGX_SUCCESS;
}

// validate txn header(that contains payload hash) with puclic key and signature
bool ValidateTxn(
    const uint8_t *serialized_header,
    uint32_t header_size,
    const char *signer_pub_key,
    const uint8_t *signature,
    const uint8_t *payload_hash,
    const uint8_t *payload,
    uint32_t payload_size)
{
    //decrypt signature with signerPublicKey, calculate hash on header and compare to decrypted header
    EC_KEY *pub_ec_key = NULL;
    public_ec_key_str_t pub_str = {};
    safe_memcpy(pub_str, sizeof(public_ec_key_str_t), signer_pub_key, strnlen(signer_pub_key, sizeof(public_ec_key_str_t)));

    if (create_public_ec_key_from_str(&pub_ec_key, &pub_str) == false)
    {
        PRINT(ERROR, LISTENER, "create_ec_public_key_from_compressed_ec_hex_str failed\n");
    }

    if (!ecdsa_verify(serialized_header,
                      header_size,
                      pub_ec_key,
                      (ecdsa_bin_signature_t *)signature))
    {
        PRINT(ERROR, LISTENER, "ecdsa_verify returned false\n");
        EC_KEY_free(pub_ec_key);
        return false;
    }
    EC_KEY_free(pub_ec_key);
    //validate payload sha512 is correct (now that we trust the value in the header)
    sha512_data_t hashRes;
    if (!sha512_msg(payload, payload_size, &hashRes))
    {
        PRINT(ERROR, LISTENER, "sha512_msg failed\n");
        return false;
    }

    if (memcmp(payload_hash, hashRes, sizeof(sha512_data_t)) == 0)
    {
        return true;
    }
    PRINT(ERROR, LISTENER, "payload sha mismatch\n");
    return false;
}

/**
1. if txn SVN > enclave SVN -> reject
2. if txn SVN != cached SVN -> update cached SVN by reading transaction context SVN and ACL address from sawtooth
3. if client SVN != updated cached SVN -> reject
 */
bool validate_svn(const uint16_t txn_svn)
{
    // if txn svn is newer than TP svn, this is a faliure
    if (txn_svn > ledger_keys_manager.get_svn())
    {
        PRINT(ERROR, ACL_LOG, "txn svn is newer than TP svn\n");
        return false;
    }
    if (txn_svn == acl::get_cached_svn())
        return true;
    //txn_svn != cached svn, update svn, read svn from sawtooth context
    if (acl::update_cached_acl(txn_svn, false))
    {
        PRINT(ERROR, ACL_LOG, "read acl svn failed\n");
        return false;
    }
    //compare svn
    return txn_svn == acl::get_cached_svn();
}

//mutex used to guard apply, making txn processing serial
std::mutex secure_apply_mtx;

sgx_status_t secure_apply(
    const uint8_t *serialized_header,
    uint32_t header_size,
    const char *nonce,
    const char *signer_pub_key,
    const uint8_t *signature,
    const uint8_t *payload_hash,
    const uint8_t *payload,
    uint32_t payload_size)
{
    // lock mutex, the mutex is released when guard gets out of scope
    std::lock_guard<std::mutex> guard(secure_apply_mtx);
    verify_enclave_role(ROLE_TP);

    //validate input
    if (serialized_header == NULL || nonce == NULL || signer_pub_key == NULL ||
        signature == NULL || payload_hash == NULL || payload == NULL || header_size == 0 ||
        payload_size == 0)
    {
        PRINT(ERROR, LISTENER, "argument check failed\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }
    auto nonce_str = secure::string(nonce);
    if (nonce_str.empty())
    {
        PRINT(ERROR, LISTENER, "argument check failed\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }
    // if public key is not compressed, compress it
    auto key_res = getKeyFromStr(signer_pub_key);
    if (!key_res.first)
        return SGX_ERROR_INVALID_PARAMETER;
    SignerPubKey key = key_res.second;

    if (!ValidateTxn(serialized_header, header_size, key.data(), signature,
                     payload_hash, payload, payload_size))
    {
        PRINT(ERROR, LISTENER, "ValidateTxn failed\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    //get client txn svn from transaction payload
    const char *data = reinterpret_cast<const char *>(payload);
    uint16_t txn_svn;
    Ledger_Reader_Writer reader;
    if (!reader.get_secure_data_svn(data, &txn_svn))
    {
        PRINT(ERROR, LISTENER, "failed to extract transaction svn\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }
    //validate svn
    if (!validate_svn(txn_svn))
    {
        PRINT(ERROR, LISTENER, "transaction svn %" PRIu16 " is not valid\n", txn_svn);
        return SGX_ERROR_INVALID_PARAMETER;
    }
    // is member will be also checked before read/write request but checked here save effort in case not a member
    if (!acl::acl_is_member(key, txn_svn, true))
    {
        PRINT(ERROR, LISTENER, "acl_is_member return false\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }
    //decrypt payload
    secure::string decrypted_payload;
    auto status = decrypt_payload(data, decrypted_payload, txn_svn);
    if (status != SGX_SUCCESS)
        return status;
    // execute logic
    if (!business_logic::execute_transaction(decrypted_payload, key, txn_svn, nonce))
        return SGX_ERROR_UNEXPECTED;

    return SGX_SUCCESS;
}
