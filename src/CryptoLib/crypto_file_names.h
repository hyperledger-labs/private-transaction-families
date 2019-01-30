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
 
#ifndef _CRYPTO_FILE_NAMES_H_
#define _CRYPTO_FILE_NAMES_H_

#define KEYS_DIR_NAME					".stl_keys"

#define SEALED_LEDGER_KEYS_FILENAME 	"ledger_sealed_keys.data"
#define LEDGER_PUBLIC_RA_KEY_FILENAME 	"ledger_public_ra_key.data"
#define LEDGER_PUBLIC_DATA_KEY_FILENAME	"ledger_public_data_key.hexstr"
#define LEDGER_PUBLIC_SIGN_KEY_FILENAME	"ledger_public_sign_key.hexstr"

// ledger owner, administrator, signs the KDS file
#define ADMIN_PRIVATE_KEY_FILENAME		"admin_private_key.hexstr"
#define ADMIN_PUBLIC_KEY_FILENAME 		"admin_public_key.hexstr"

// specific user keys
#define CLIENT_PRIVATE_KEY_FILENAME		"client_private_key.hexstr"
#define CLIENT_PUBLIC_KEY_FILENAME 		"client_public_key.hexstr"

#endif // _CRYPTO_FILE_NAMES_H_
