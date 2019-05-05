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

#include <stdio.h>
#include <memory>

#include "enclave_log.h"
#include "crypto_enclave.h"
#include "businessLogic.h"
#include "tclient_reader.h"
#include "Enclave_t.h"
#include "acl_read_write.h"
#include "crypto_ledger_reader_writer.h"
#include "enclave_role.h"
#ifdef DEBUG
#include "tmemory_debug.h"
#endif


Tclient_Reader_Data_Map data_map;

bool validate_svn(const uint16_t &client_svn)
{
	// if client svn != TP svn, this is a faliure
	if (client_svn != ledger_keys_manager.get_svn())
	{
		PRINT(ERROR, ACL_LOG, "client svn is different than TP svn\n");
		return false;
	}
	if (client_svn == acl::get_cached_svn())
		return true;
	//txn_svn != cached svn, update svn, read svn from sawtooth context
	if (acl::update_cached_acl(client_svn, true))
	{
		PRINT(ERROR, ACL_LOG, "read acl svn failed\n");
		return false;
	}
	//compare svn
	return client_svn == acl::get_cached_svn();
}

// Process client request
uint64_t enclave_client_read(const char *b64_input_str, uint32_t *output_size)
{
	verify_enclave_role(ROLE_TP);

	if (ledger_keys_manager.keys_ready() == false)
	{
		PRINT(ERROR, SERVER, "ledger keys are not initialized\n");
		return 0;
	}

	if (b64_input_str == NULL || output_size == NULL)
	{
		PRINT(ERROR, SERVER, "wrong input parameters\n");
		return 0;
	}

	size_t min_request_size_b64 = 4 * (sizeof(secure_data_t)/3);
	size_t max_request_size = (sizeof(secure_data_t) + MAX_DATA_LEN);
	size_t max_request_size_b64 = (4 * (max_request_size/3))+3;
	size_t request_size = strnlen(b64_input_str, max_request_size_b64);// should be ~ 1.33 * (sizeof(secure_data_t) + data_size)
	if (request_size < min_request_size_b64)
	{
		PRINT(ERROR, SERVER, "input string is too short\n");
		return 0;
	}
	if (request_size >= max_request_size_b64)
	{
		PRINT(ERROR, SERVER, "input string is too long\n");
		return 0;
	}

	Ledger_Reader_Writer reader;

	reader.set_svn(ledger_keys_manager.get_svn());

	if (reader.set_data_keys(&(ledger_keys_manager.get_current_ledger_keys()->data_pub_ec_key_str), &(ledger_keys_manager.get_current_ledger_keys()->data_priv_ec_key_str)) == false)
	{
		PRINT(ERROR, SERVER, "set_data_keys failed\n");
		return 0;
	}
	
	if (reader.set_signing_keys(ledger_keys_manager.get_public_signing_key(), ledger_keys_manager.get_private_signing_key()) == false)
	{
		PRINT(ERROR, SERVER, "set_signing_keys failed\n");
		return 0;
	}

	// get the request svn (could be older then the current svn, for not updated svns)
	uint16_t svn;
	if (reader.get_secure_data_svn(b64_input_str, &svn) == false)
	{
		PRINT(ERROR, LISTENER, "failed to read svn from the read request\n");
		return SGX_ERROR_INVALID_PARAMETER;
	}
	// update cached SVN if differetn than enclace/client svn
	if (!validate_svn(svn))
	{
		PRINT(ERROR, SERVER, "read request SVN failure\n");
		return 0;
	}

	secure_data_content_t *p_request_data = nullptr;
	size_t data_size = 0;
	SignerPubKey client_pub_key_buf = {0};
	// decode secure data will malloc p_request_data
	if (reader.decode_secure_data(b64_input_str,  &p_request_data, &data_size, (public_ec_key_str_t *)&client_pub_key_buf) == false)
	{
		PRINT(ERROR, SERVER, "decode_secure_data failed\n");
		return 0;
	}

	StlAddress addr_buf = {};
	safe_memcpy(addr_buf.val.data(), addr_buf.val.size(), p_request_data->address, sizeof(ledger_hex_address_t));

	// todo - we assume here that the data is a string...
	secure::string ledger_data = "";
	//if p_request_data->data is not empty it contains the encrypted address data, pass it to the read request.
	if (data_size > sizeof(secure_data_content_t))
	{
		ledger_data = secure::string(p_request_data->data, p_request_data->data + (data_size - sizeof(secure_data_content_t)));
	}
	if (!business_logic::bl_read(addr_buf, client_pub_key_buf, ledger_data, svn))
	{
		PRINT(ERROR, SERVER, "acl_read failed\n");
		memset_s(addr_buf.val.data(), addr_buf.val.size(), 0, addr_buf.val.size());
		if(p_request_data != nullptr)
		{
			memset_s(p_request_data, data_size, 0, data_size);
			free(p_request_data);
			p_request_data = nullptr;
		}
		return 0;
	}
	memset_s(addr_buf.val.data(), addr_buf.val.size(), 0, addr_buf.val.size());
	// todo - return value?
	// todo - is it always an hex string? if so can remove the parameter and use strlen

	if (ledger_data.size() > ONE_GB) // data above 2 GB can cause issues with calculations, we use integers for some math, leave it a 1 GB to be safe. it is also converted with b64 which increase it...
	{
		PRINT(ERROR, SERVER, "address content is too big, can't process (size: %ld)\n", ledger_data.size());
		if(p_request_data != nullptr)
		{
			memset_s(p_request_data, data_size, 0, data_size);
			free(p_request_data);
			p_request_data = nullptr;
		}
		return 0;
	}

	char* b64_response = nullptr;
	if (reader.encode_secure_data(p_request_data->address, (const uint8_t*)ledger_data.c_str(), ledger_data.size()+1, TYPE_READER_RESPONSE, &b64_response) == false)
	{
		PRINT(ERROR, SERVER, "encode_secure_data failed\n");
		if(p_request_data != nullptr)
		{
			memset_s(p_request_data, data_size, 0, data_size);
			free(p_request_data);
			p_request_data = nullptr;
		}
		return 0;
	}
	if(p_request_data != nullptr)
	{
		memset_s(p_request_data, data_size, 0, data_size);
		free(p_request_data);
		p_request_data = nullptr;
	}
	secure::string s_b64_response(b64_response);
	*output_size = s_b64_response.size() + 1;
	return (data_map.add_data(s_b64_response));
}

int enclave_client_get_encrypted_data(uint64_t id, char *output_buffer, uint32_t output_size)
{
	verify_enclave_role(ROLE_TP);

	secure::string b64_response;

	if (id == 0 || output_buffer == NULL)
	{
		PRINT(ERROR, SERVER, "bad input parameters\n");
		return -1;
	}

	b64_response = data_map.get_data(id);

	if (b64_response.empty())
	{
		PRINT(ERROR, SERVER, "the id was not found\n");
		return -1;
	}

	uint32_t expected_size = b64_response.length() + 1;

	if (output_size != expected_size)
	{
		PRINT(ERROR, SERVER, "incorrect input size\n");
		return -1;
	}

	safe_memcpy(output_buffer, output_size, b64_response.c_str(), expected_size);

	return 0;
}
