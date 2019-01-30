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
 
#ifndef _CRYPTO_KDF_STRINGS_H_
#define _CRYPTO_KDF_STRINGS_H_

// this should be changed for other ledger projects
#define LEDGER_ADMIN "TASE"

// todo - give better string names

// used for deriving the previous svn kds from the current kds
#define KDS_1ST_DERIVATION_LABEL	LEDGER_ADMIN"-SGX-LEDGER-KDS-DERIVATION-KEY"
#define KDS_2ND_DERIVATION_LABEL 	LEDGER_ADMIN"-SGX-LEDGER-KEY-DERIVATION-SECRET"

// create the main ec key (pseudo-random output for the ec_generate_key function), 
// the resulting ec key is used when creating encryption keys for secret input data, and for signing secret output data
#define ECKEY_1ST_DERIVATION_LABEL		LEDGER_ADMIN"-SGX-LEDGER-SEED-DERIVATION-FROM-KDS"
#define ECKEY_DATA_2ND_DERIVATION_LABEL	LEDGER_ADMIN"-SGX-LEDGER-ENCRYPTION-SEED-DERIVATION"
#define ECKEY_SIGN_2ND_DERIVATION_LABEL	LEDGER_ADMIN"-SGX-LEDGER-SIGNING-SEED-DERIVATION"

// create HMAC key, used for hashing secret data and placing the hash in the untrusted sawtooth database
#define HMAC_1ST_DERIVATION_LABEL	LEDGER_ADMIN"-SGX-LEDGER-SEALING-KEY-DERIVATION-KEY"
#define HMAC_2ND_DERIVATION_LABEL 	LEDGER_ADMIN"-SGX-LEDGER-RECORD-SEALING-KEY"

// generating various aes keys
#define AES_1ST_DERIVATION_LABEL				LEDGER_ADMIN"-SGX-LEDGER-SHARED-KEY-DERIVATION-KEY"
#define AES_REQUEST_2ND_DERIVATION_LABEL		LEDGER_ADMIN"-SGX-LEDGER-READ-REQUEST-ENCRYPTION-KEY"
#define AES_RESULT_2ND_DERIVATION_LABEL 		LEDGER_ADMIN"-SGX-LEDGER-READ-RESULT-ENCRYPTION-KEY"
#define AES_TRANSACTION_2ND_DERIVATION_LABEL	LEDGER_ADMIN"-SGX-LEDGER-TRANSACTION-DATA-ENC-KEY"


#endif // _CRYPTO_KDF_STRINGS_H_
