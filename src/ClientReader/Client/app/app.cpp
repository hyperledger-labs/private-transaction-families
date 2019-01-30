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
#include <string.h>
#include <stdint.h>
#include <malloc.h>

#include <chrono>

#include "app_log.h"
#include "client_network.h"
#include "crypto_ledger_reader_writer.h"

#include "openssl/crypto.h"

void print_usage(char* filename)
{
	printf("usage:\n%s read-address [options]\n", filename);
	printf("%s -h - prints this info\n", filename);
	printf("%s --help - prints this info\n", filename);
	printf("options:\n");
	printf("\t-svn svn_value - set the svn value used in the request, should match the destination server svn\n");
	printf("\t-loops loops_count - for stress testing, run the read request loops_count times\n");
	printf("\t-server_ip ip - specify the server ip to connect to\n");
	printf("\t-server_port port - spepicfy the server port to connect to\n");
	printf("\twithout optional parameters - connect to local machine with the default port (%d), use svn=1, and run only once\n", CLIENT_READER_PORT_NUMBER);
	printf("\tif loop-count is bigger than 100, performance data will be printed, better compiled with PERFORMANCE=1\n");
}

int main(int argc, char* argv[])
{	
	bool res = false;
	int ret = 1;
	int retval = 1;
	size_t size = 0;
	uint16_t svn = 1;
	int socket = -1;
	char* request_str = NULL;
	char* response_str = NULL;
	secure_data_content_t* secure_data = NULL;
	ledger_hex_address_t address = {0};
	network_packet_t packet = {};
	Ledger_Reader_Writer* reader = new Ledger_Reader_Writer();
	uint64_t loops = 1;
	const char* server_ip = CLIENT_READER_SERVER_IP;
	uint16_t server_port = CLIENT_READER_PORT_NUMBER;
	
	auto start = std::chrono::steady_clock::now();
	auto end = std::chrono::steady_clock::now();
	
	// parse input parameters
		
	if (argc < 2 || argc % 2 == 1) // (binary+address) + (option+value)*x
	{
		print_usage(argv[0]);
		return 1;
	}
	
	if (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
	{
		print_usage(argv[0]);
		return 0;
	}
	
	// argv[0] - binary name
	// argv[1] - address
	for (int i = 2 ; i < argc ; i++)
	{
		if (strcmp(argv[i], "-svn") == 0)
		{
			i++;
			svn = (uint16_t)strtoul(argv[i], NULL, 10);
			continue;
		}
		
		if (strcmp(argv[i], "-loops") == 0)
		{
			i++;
			loops = strtoul(argv[i], NULL, 10);
			continue;
		}
		
		if (strcmp(argv[i], "-server_ip") == 0)
		{
			i++;
			server_ip = argv[i];
			continue;
		}
		
		if (strcmp(argv[i], "-server_port") == 0)
		{
			i++;
			server_port = (uint16_t)strtoul(argv[i], NULL, 10);
			continue;
		}
		
		printf("unknown option %s\n", argv[i]);
		print_usage(argv[0]);
		return 1;
	}
	
	size_t addr_len = strlen(argv[1]);
	if (addr_len > sizeof(ledger_hex_address_t)-1)
	{
		PRINT(ERROR, MAIN, "address length is too long\n");
		return 1;
	}
	
	memset(address, '0', sizeof(ledger_hex_address_t)-1); // fill with basic 'hex' character
	memcpy(address, argv[1], addr_len);
	
#ifdef DEBUG
#ifndef PERFORMANCE
	CRYPTO_set_mem_debug(1);
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
#endif
#endif

	for (uint64_t counter = 0 ; counter < loops ; counter++)
	{
		socket = client_connect_to_server(server_ip, server_port);
		if (socket < 0)
		{
			PRINT(ERROR, MAIN, "failed to connect to localhost server\n");
			break;
		}
		
		do
		{
			reader->set_svn(svn);
			
			res = reader->load_keys_from_files();
			if (res == false)
			{
				PRINT(ERROR, MAIN, "load_keys_from_files failed\n");
				break;
			}
			
			res = reader->encode_secure_data(address, NULL, 0, TYPE_READER_REQUEST, &request_str);
			if (res == false || request_str == NULL)
			{
				PRINT(ERROR, MAIN, "client_encrypt_request failed\n");
				break;
			}
			
			packet.type = TYPE_CLIENT_READER;
			packet.size = (uint32_t)strlen(request_str) + 1;
			
			//PRINT(INFO, MAIN, "encoded request (%d bytes):\n%s\n", packet.size, request_str);
								
			ret = client_exchange_data_with_server(socket, &packet, request_str, &response_str);
			if (ret != 0)
			{
				PRINT(ERROR, MAIN, "server_exchange_data returned error %d\n", ret);
				break;
			}	
			
			res = reader->decode_secure_data(response_str, &secure_data, &size, NULL);
			if (res == false)
			{
				PRINT(ERROR, MAIN, "client_decrypt_response failed\n");
				break;
			}
			
			if (secure_data != NULL)
				PRINT(INFO, MAIN, "\"%s\" data: %s\n", argv[1], secure_data->data);
				
			retval = 0;

		} while(0);
		
		if (request_str != NULL) // allocated in reader.encode_secure_data
		{
			free(request_str);
			request_str = NULL;
		}
		
		if (response_str != NULL) // allocate in client_exchange_data_with_server
		{
			free(response_str);
			response_str = NULL;
		}
		
		if (secure_data != NULL) // allocated in reader.decode_secure_data
		{
			free(secure_data);
			secure_data = NULL;
		}
	
		client_disconnect_from_server(socket);
		
		if (loops > 100)
		{
			if (counter % 100 == 99)
			{
				end = std::chrono::steady_clock::now();
				auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
				long loops_per_second = 100000 / elapsed.count();
				PRINT(ERROR, MAIN, "counter: %ld, requests per second: %ld\n", counter+1, loops_per_second); // print with ERROR so PERFORMANCE macro won't disable it
				start = std::chrono::steady_clock::now();
			}
		}
			
		if (retval == 1) // failure, break the loop
			break;
		
		if (counter+1 < loops) // success, not final loop
			retval = 1;
	}
	
	delete reader;

#ifdef DEBUG
#ifndef PERFORMANCE
	CRYPTO_mem_leaks_fp(stdout);
#endif
#endif

	if (retval == 0)
	{
		PRINT(INFO, MAIN, "finished with success!\n");
	}
	else
	{
		PRINT(ERROR, MAIN, "finished with failure!\n");
	}
	
	return retval;
}


