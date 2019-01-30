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
 
#ifndef _CRYPTO_STL_READER_WRITER_WRAPPER_H_
#define _CRYPTO_STL_READER_WRITER_WRAPPER_H_

#include "crypto_ledger_reader_writer.h"
#include "secure_allocator.h"

class Ledger_Reader_Writer_Wrapper : public Ledger_Reader_Writer
{
public:
bool encode_secure_data_wrapper(const ledger_hex_address_t address, secure::string& data, size_t size,request_type_e type, secure::string& response);

bool decode_secure_data_wrapper(const secure::string& b64_request_str, secure_data_content_t &output_response, size_t& output_size, public_ec_key_str_t* p_remote_pub_key_str);
};

#endif // _CRYPTO_STL_READER_WRITER_WRAPPER_H_
