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

namespace listener
{

// class for handling access to sawtooth rest api,
// used for supporting client reader read requests
class RestHandler final
{
  public:
	std::string read_from_rest_api(const std::string &address) const;

  private:
	std::string decode_base_64(const std::string &in) const;
	std::string get_data_from_json(const std::string &data) const;
};

size_t writeFunction(void *ptr, size_t size, size_t nmemb, std::string *data);

} // namespace listener
