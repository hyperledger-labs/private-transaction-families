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
	// if this is first boot after restart, update svn and acl cache from ledger
    std::array<uint8_t, 64> empty_hash = {};
    bool updated = false;
	if (acl::get_acl_hash() == empty_hash)
	{
		//cache is empty (first action after restart), update it
        if (!acl::update_cached_acl(client_svn, true))
        {
            PRINT(ERROR, ACL_LOG, "read acl svn failed\n");
            return false;
        }
        updated = true;
	}
	if (client_svn == acl::get_cached_svn())
		return true;
	//txn_svn != cached svn, update svn, read svn from sawtooth context
	if (updated) // if allready updated, there is svn mismatch
        return false;
	if (!acl::update_cached_acl(client_svn, true))
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
	secure::string read_respond = "";
	//if p_request_data->data is not empty it contains the encrypted address data or txn, pass it to the read request.
	if (data_size > sizeof(secure_data_content_t))
	{
		// if first byte is 0 this is a txn read reqeust else it is a data read request
		if (p_request_data->data[0] == 0)//read txn request
		{
			// decode again!
			if (client_pub_key_buf != acl::get_admin_key())
			{
				PRINT(ERROR, SERVER, "only admin can read transactions\n");
				PRINT(INFO, SERVER, "txn read request public key is:\n");
				print_byte_array(&client_pub_key_buf, sizeof(public_ec_key_str_t));
				if(p_request_data != nullptr)
				{
					memset_s(p_request_data, data_size, 0, data_size);
					free(p_request_data);
					p_request_data = nullptr;
				}
				return 0;
			}
			// decode secure data will malloc p_request_data_payload
			secure_data_content_t *p_request_data_payload = nullptr;
			size_t data_size_payload = 0;
			secure::string txn_payload(p_request_data->data +1, p_request_data->data + (data_size - sizeof(secure_data_content_t)));
			Ledger_Reader_Writer txn_reader;
			uint16_t txn_svn;
			if (!txn_reader.get_secure_data_svn(txn_payload.c_str(), &txn_svn))
			{
				PRINT(ERROR, LISTENER, "failed to extract transaction svn\n");
				if(p_request_data != nullptr)
				{
					memset_s(p_request_data, data_size, 0, data_size);
					free(p_request_data);
					p_request_data = nullptr;
				}
				return 0;
			}
			if (txn_svn > ledger_keys_manager.get_svn())
			{
				PRINT(ERROR, LISTENER, "read txn payload svn is newer than enclave svn\n");
				if(p_request_data != nullptr)
				{
					memset_s(p_request_data, data_size, 0, data_size);
					free(p_request_data);
					p_request_data = nullptr;
				}
				return 0;
			}
			txn_reader.set_svn(ledger_keys_manager.get_svn());
			// set the keys to the ones corresponding to the txn payload svn, otherwise the calculated key would be wrong
			if (txn_reader.set_data_keys(&(ledger_keys_manager.get_ledger_keys_by_svn(txn_svn)->data_pub_ec_key_str),
									&(ledger_keys_manager.get_ledger_keys_by_svn(txn_svn)->data_priv_ec_key_str)) == false)
			{
				PRINT(ERROR, SERVER, "set_data_keys failed\n");
				if(p_request_data != nullptr)
				{
					memset_s(p_request_data, data_size, 0, data_size);
					free(p_request_data);
					p_request_data = nullptr;
				}
				return 0;
			}
			if (txn_reader.decode_secure_data(txn_payload.c_str(),  &p_request_data_payload, &data_size_payload, NULL) == false)
			{
				PRINT(ERROR, SERVER, "decode_secure_data txn payload failed\n");
				if(p_request_data != nullptr)
				{
					memset_s(p_request_data, data_size, 0, data_size);
					free(p_request_data);
					p_request_data = nullptr;
				}
				return 0;
			}
			read_respond = secure::string(p_request_data_payload->data, p_request_data_payload->data + (data_size_payload - sizeof(secure_data_content_t)));
			if(p_request_data_payload != nullptr)
			{
				memset_s(p_request_data_payload, data_size_payload, 0, data_size_payload);
				free(p_request_data_payload);
				p_request_data_payload = nullptr;
			}
		}
		else // read address data
		{
			// cast data to struct, for each instance of struct try to read and if fail return false
			auto offset = 1;
			secure_addresses_data_t* sadt = reinterpret_cast<secure_addresses_data_t*>(p_request_data->data);
			read_respond.append("{\"data\": [");
			for (int i = 0; i < sadt->num_of_addresses; i++)
			{
				// get address and data from p_request_data->data
				// first cast to uint8_t to advance pointer by offset of bytes
				secure_address_data_t* addr_data_s = reinterpret_cast<secure_address_data_t*>(static_cast<uint8_t*>(p_request_data->data) + offset);
				safe_memcpy(addr_buf.val.data(), addr_buf.val.size(), addr_data_s->address, sizeof(ledger_hex_address_t));
				read_respond.append("{");
				read_respond.append("\"address\": \"");
				read_respond.append(addr_data_s->address);
				secure::string addr_data = secure::string(addr_data_s->data, addr_data_s->data + addr_data_s->data_size);
				// advance offset for next rotation
				offset += sizeof(secure_address_data_t) + addr_data_s->data_size;
				// read data using ACL:
				if (!business_logic::bl_read(addr_buf, client_pub_key_buf, addr_data, svn))
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
				read_respond.append("\", \"data\": ");
				read_respond.append(addr_data);
				read_respond.append("},");
			}
			// remove last ',' and close list
			read_respond.pop_back();
			read_respond.append("]}");
		}
	}
	// else, then p_request_data->data is empty, read data from ledger
	else if (!business_logic::bl_read(addr_buf, client_pub_key_buf, read_respond, svn))
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


	if (read_respond.size() > ONE_GB) // data above 2 GB can cause issues with calculations, we use integers for some math, leave it a 1 GB to be safe. it is also converted with b64 which increase it...
	{
		PRINT(ERROR, SERVER, "address content is too big, can't process (size: %ld)\n", read_respond.size());
		if(p_request_data != nullptr)
		{
			memset_s(p_request_data, data_size, 0, data_size);
			free(p_request_data);
			p_request_data = nullptr;
		}
		return 0;
	}

	char* b64_response = nullptr;
	if (reader.encode_secure_data(p_request_data->address, (const uint8_t*)read_respond.c_str(), read_respond.size()+1, TYPE_READER_RESPONSE, &b64_response) == false)
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
	free(b64_response);
	b64_response = nullptr;
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
