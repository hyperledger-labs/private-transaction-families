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
 
#include "crypto_stl_reader_writer_wrapper.h"

#include <string.h>
#include <vector>
#include <iostream>
#include "enclave_log.h"
#include <memory>
#include <inttypes.h>



    bool Ledger_Reader_Writer_Wrapper::encode_secure_data_wrapper(const ledger_hex_address_t address, secure::string& data, size_t size,request_type_e type, secure::string& response)
	{
		char* output;
		bool retval = false;

		if((retval = encode_secure_data(address, (const uint8_t*)data.c_str(), (uint32_t)size + 1, type, &output)) == true)
        {
             response = secure::string(output);
        }

        if(output != nullptr)
        {
            free(output);
        }

        return retval;
	} 




    bool Ledger_Reader_Writer_Wrapper::decode_secure_data_wrapper(const secure::string& b64_request_str, secure_data_content_t &output_response, size_t& output_size, public_ec_key_str_t* p_remote_pub_key_str)	  
   {
        secure_data_content_t* response = nullptr;

        bool retval = false;
      

        if ((retval = decode_secure_data(b64_request_str.c_str(), &response,  &output_size, p_remote_pub_key_str)) == true)
        {   
            output_response = *response;
        }

        if(response != nullptr)
        {
            memset_s(response, sizeof(secure_data_content_t), 0, sizeof(secure_data_content_t)); 
		    free(response);
        } 
        
        return retval;

    }

   
