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
#include "rest_handler.h"
#include <vector>
#include <curl/curl.h>
#include "config.h"

namespace listener
{

const static std::string base_64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// TODO use openssl instead of our own function
std::string RestHandler::decode_base_64(const std::string &in) const
{
	std::string out = "";
	std::vector<int> T(256, -1);
	for (int i = 0; i < 64; i++)
		T[base_64_chars[i]] = i;

	int val = 0, valb = -8;
	for (unsigned char c : in)
	{
		if (T[c] == -1)
			break;
		val = (val << 6) + T[c];
		valb += 6;
		if (valb >= 0)
		{
			out.push_back(char((val >> valb) & 0xFF));
			valb -= 8;
		}
	}
	return out;
}

// TODO use nlohmann instead of using our own function
//get hash data from rest api json read result
std::string RestHandler::get_data_from_json(const std::string &data) const
{
	std::string data_key_str = "\"data\": \"";
	size_t start_pos = data.find(data_key_str, 0);
	if (start_pos == std::string::npos)
	{
		return "";
	}
	start_pos += data_key_str.size();
	size_t end_pos = data.find("\"", start_pos);
	if (end_pos == std::string::npos)
	{
		return "";
	}
	return data.substr(start_pos, end_pos - start_pos);
}

//write function to be used by curl requst
size_t writeFunction(void *ptr, size_t size, size_t nmemb, std::string *data)
{
	data->append((char *)ptr, size * nmemb);
	return size * nmemb;
}

//use curl to read data using sawtooth rest api
std::string RestHandler::read_from_rest_api(const std::string &address) const
{
	CURL *curl = curl_easy_init();
	std::string ret_str;
	if (curl)
	{
		std::string url("" + config::g_rest_url + "/state/" + address);
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeFunction);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ret_str);
		curl_easy_setopt(curl, CURLOPT_PROXY, "");
		/* Perform the request, res will get the return code */
		CURLcode res = curl_easy_perform(curl);
		/* Check for errors */
		if (res != CURLE_OK)
		{
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
					curl_easy_strerror(res));
			ret_str = "";
		}
		/* always cleanup */
		curl_easy_cleanup(curl);
		curl = NULL;
		curl_global_cleanup();
	}
	if (ret_str.size() != 0)
	{
		//extract data from json
		std::string base_64_res = get_data_from_json(ret_str);
		if (base_64_res == "")
		{
			return "";
		}
		ret_str = decode_base_64(base_64_res);
	}
	return ret_str;
}
} // namespace listener
