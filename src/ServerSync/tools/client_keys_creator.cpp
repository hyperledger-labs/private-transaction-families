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
 
#include "crypto.h"
#include "app_log.h"

int main(int argc, char* argv[])
{
	int retval = 1;
	EC_KEY* ec_key = NULL;
	
	// not using any input
	(void)argc;
	(void)argv;
	
	do {
		// create a new key
		if (create_new_ec_key_pair(&ec_key) == false)
		{
			PRINT(ERROR, MAIN, "create_new_ec_key_pair failed\n");
			break;
		}

		if (save_public_ec_key_to_file(ec_key, CLIENT_PUBLIC_KEY_FILENAME) == false)
		{
			PRINT(ERROR, MAIN, "save_public_ec_key_to_file failed\n");
			break;
		}

		if (save_private_ec_key_to_file(ec_key, CLIENT_PRIVATE_KEY_FILENAME) == false)
		{
			PRINT(ERROR, MAIN, "save_private_ec_key_to_file failed\n");
			break;
		}
		
		PRINT(INFO, MAIN, "keys files created successfully\n");
		
		retval = 0;
		
	} while(0);
	
	if (ec_key != NULL)
		EC_KEY_free(ec_key);
	
	return retval;
}
