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
#include <errno.h>

#include <string>

#include <sys/stat.h>
#include <sys/types.h>

#include "app_log.h"
#include "config.h"
#include "crypto_file_names.h"

#include "Enclave_u.h"


std::string config::g_key_path; // path to key files


bool get_full_file_name(const char* filename, std::string& full_name)
{
	if (config::g_key_path.empty() == true) // use default path
	{
		char* home_dir = getenv("HOME");
		if (home_dir == NULL)
		{
			PRINT(ERROR, MAIN, "getenv 'HOME' failed\n");
			return false;
		}
		config::g_key_path = home_dir;
		config::g_key_path += "/";
		config::g_key_path += KEYS_DIR_NAME;
		
		// create the folder if it doesn't exist
		struct stat st = {};
		if (stat(config::g_key_path.c_str(), &st) == -1) 
		{
			PRINT(INFO, OCALL, "creating keys directory %s\n", config::g_key_path.c_str());
			if (mkdir(config::g_key_path.c_str(), 0777) != 0)
			{
				PRINT(ERROR, CRYPTO, "mkdir for keys folder failed\n");
				return false;
			}
		}
		
		config::g_key_path += "/";
	}
	
	full_name = config::g_key_path + filename;
	
	return true;
}

/* OCALLS */

sgx_status_t save_key_to_file(const char* filename, uint8_t* data, uint32_t data_size)
{
	if (filename == NULL || data == NULL || data_size == 0)
		return SGX_ERROR_INVALID_PARAMETER;
	
	std::string full_name;
	if (get_full_file_name(filename, full_name) == false)
	{
		PRINT(ERROR, OCALL, "get_full_file_name failed\n");
		return SGX_ERROR_UNEXPECTED;
	}
	
	FILE* f = fopen(full_name.c_str(), "w");
	if (f == NULL)
	{
		PRINT(ERROR, OCALL, "can't open file %s, errno %d\n", full_name.c_str(), errno);
		return SGX_ERROR_UNEXPECTED;
	}

	size_t count = fwrite(data, data_size, 1, f);
	fclose(f);
	if (count != 1)
	{
		PRINT(ERROR, OCALL, "fwrite failed with errno %d\n", errno);
		return SGX_ERROR_UNEXPECTED;
	}
	
	PRINT(INFO, OCALL, "wrote %d bytes to %s\n", data_size, full_name.c_str());

	return SGX_SUCCESS;	
}


sgx_status_t read_key_from_file(const char* filename, uint8_t* data, uint32_t data_size)
{
	if (filename == NULL || data == NULL || data_size == 0)
		return SGX_ERROR_INVALID_PARAMETER;
		
	std::string full_name;
	if (get_full_file_name(filename, full_name) == false)
	{
		PRINT(ERROR, OCALL, "get_full_file_name failed\n");
		return SGX_ERROR_UNEXPECTED;
	}
	
	FILE* f = fopen(full_name.c_str(), "r");
	if (f == NULL)
	{
		PRINT(ERROR, OCALL, "can't open file %s, errno %d\n", full_name.c_str(), errno);
		return SGX_ERROR_UNEXPECTED;
	}
	
	fseek(f, 0, SEEK_END);
	size_t len = ftell(f);
	
	if (len < data_size)
	{
		fclose(f);
		PRINT(ERROR, OCALL, "file size is too small (size: %ld, needed %d)\n", len, data_size);
		return SGX_ERROR_UNEXPECTED;
	}
		
	fseek(f, 0, SEEK_SET);
	
	size_t count = fread(data, data_size, 1, f);
	fclose(f);
	if (count != 1)
	{
		PRINT(ERROR, OCALL, "fread failed with errno %d\n", errno);
		return SGX_ERROR_UNEXPECTED;
	}

	return SGX_SUCCESS;
}


void uprint(int level, const char* str)
{	
	if (level == ERROR)
	{
		PRINT_TIME(stderr);
		fputs(str, stderr);
	}
	else if (level == INFO)
	{
		PRINT_TIME(stdout);
		fputs(str, stdout);
	}
	else // PLAIN
	{
		fputs(str, stdout);
	}
}
