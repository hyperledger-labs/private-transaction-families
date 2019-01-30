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
#include "app.h"
#include <errno.h>
#include <sys/stat.h>
#include <string>
#include <iostream>
#include <ctype.h>
#include <cstring>
#include <algorithm>
#include <string>

#include "exceptions.h"
#include "sawtooth_sdk.h"
#include "txn_handler.h"
#include "config.h"
#include "txn_handler.h"
#include "server_network.h"
#include "ecall_wrapper.h"
#include "config.h"

#include "log4cxx/logger.h"
#include "log4cxx/basicconfigurator.h"
#include "log4cxx/level.h"

#ifdef SGX_ENCLAVE
#include "enclave_log.h"
#else
#include "app_log.h"
#endif

#define VALIDATOR_URL_PREFIX "tcp://"
#define VALIDATOR_URL_PREFIX_LEN 6
#define VALIDATOR_URL_DEFAULT "tcp://127.0.0.1:4004"
#define REST_URL_PREFIX "http://"
#define REST_URL_PREFIX_LEN 7
#define REST_URL_DEFAULT "http://127.0.0.1:8008"
#define ENCLAVE_NAME "Enclave.signed.so"

//define of external globals
std::string config::g_rest_url;
sgx_enclave_id_t eid;

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("sawtooth.PrivateIntKeyCXX"));

void Usage(bool bExit = false, int exitCode = 1)
{
	std::cout << "Usage" << std::endl;
	std::cout << "TestApp [-C|--connect_string] [connect_string] [-R|--rest_url] [rest_url] [-K|--keys_dir] [keys_dir]" << std::endl;
	std::cout << "  -h, --help - print help message" << std::endl;

	std::cout << "  connect_string - connect string to validator in format tcp://host:port, default is " << VALIDATOR_URL_DEFAULT
			  << std::endl;
	std::cout << "  ret_url - url of rest api in format http://host:port, default is " << REST_URL_DEFAULT
			  << std::endl;
	std::cout << "  keys_dir - full path to directory containing the ledger keys, default is ~/.stl_keys/" << std::endl;
	if (bExit)
	{
		exit(exitCode);
	}
}

bool TestConnectString(const char *str)
{
	const char *ptr = str;

	if (0 == strncmp(str, VALIDATOR_URL_PREFIX, VALIDATOR_URL_PREFIX_LEN))
	{
		ptr = str + VALIDATOR_URL_PREFIX_LEN;
	}
	else if (0 == strncmp(str, REST_URL_PREFIX, REST_URL_PREFIX_LEN))
	{
		ptr = str + REST_URL_PREFIX_LEN;
	}
	else
		return false;

	if (!isdigit(*ptr))
	{
		if (*ptr == ':' || (ptr = strchr(ptr, ':')) == NULL)
		{
			return false;
		}
		ptr++;
	}
	else
	{
		for (int i = 0; i < 4; i++)
		{
			if (!isdigit(*ptr))
			{
				return false;
			}

			ptr++;
			if (isdigit(*ptr))
			{
				ptr++;
				if (isdigit(*ptr))
				{
					ptr++;
				}
			}

			if (i < 3)
			{
				if (*ptr != '.')
				{
					return false;
				}
			}
			else
			{
				if (*ptr != ':')
				{
					return false;
				}
			}
			ptr++;
		}
	}

	for (int i = 0; i < 4; i++)
	{
		if (!isdigit(*ptr))
		{
			if (i == 0)
			{
				return false;
			}
			break;
		}
		ptr++;
	}

	if (*ptr != 0)
	{
		return false;
	}

	return true;
}

bool cmdOptionExists(char **begin, char **end, const std::string &option1, const std::string &option2)
{
	return std::find(begin, end, option1) != end || std::find(begin, end, option2) != end;
}

char *getCmdOption(char **begin, char **end, const std::string &option1, const std::string &option2)
{
	char **itr = std::find(begin, end, option1);
	if (itr != end && ++itr != end)
	{
		return *itr;
	}
	if (!option2.empty())
	{
		itr = std::find(begin, end, option2);
		if (itr != end && ++itr != end)
		{
			return *itr;
		}
	}
	return 0;
}

void parseArgs(int argc, char **argv, std::string &connectStr)
{

	if (cmdOptionExists(argv, argv + argc, "-h", "--help"))
	{
		Usage(true, 0);
	}
	char *val_url = getCmdOption(argv, argv + argc, "-C", "--connect_string");
	if (val_url)
	{
		if (!TestConnectString(val_url))
		{
			std::cout << "Validator url is not in format tcp://host:port - "
					  << val_url << std::endl;
			Usage(true);
		}
		else
		{
			connectStr = val_url;
		}
	}
	char *rest_url = getCmdOption(argv, argv + argc, "-R", "--rest_url");
	if (rest_url)
	{
		if (!TestConnectString(rest_url))
		{
			std::cout << "Rest url is not in format http://host:port - "
					  << rest_url << std::endl;
			Usage(true);
		}
		else
		{
			config::g_rest_url = rest_url;
		}
	}
	else
	{
		config::g_rest_url = REST_URL_DEFAULT;
	}
	char *keys_dir = getCmdOption(argv, argv + argc, "-K", "--keys_dir");
	if (keys_dir)
	{
		//check if dir exists
		struct stat statbuf;
		if (stat(keys_dir, &statbuf) != -1)
		{
			if (S_ISDIR(statbuf.st_mode))
			{
				config::g_key_path = keys_dir;
			}
			else
			{
				std::cout << "ledger keys dir: " << keys_dir << ", is not a directory " << std::endl;
				Usage(true);
			}
		}
		else
		{
			std::cout << "failed to stat ledger keys dir: "
					  << keys_dir << ", " << std::strerror(errno) << std::endl;
			Usage(true);
		}
	}
}

int load_enclave()
{
	sgx_status_t status;
	sgx_launch_token_t token;
	int updated;

	status = sgx_create_enclave(ENCLAVE_NAME, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (status != SGX_SUCCESS)
	{
		printf("sgx_create_enclave error 0x%x\n", status);
		return 1;
	}

	return 0;
}

void StartTP(const std::string &connectString)
{
	// Set up a simple configuration that logs on the console.
	//this is needed
	log4cxx::BasicConfigurator::configure();

	// Create a transaction processor and register our
	// handlers with it.
	sawtooth::TransactionProcessor *p =
		sawtooth::TransactionProcessor::Create(connectString);
	sawtooth::TransactionProcessorUPtr processor(p);

	sawtooth::TransactionHandlerUPtr transaction_handler(
		new txn_handler::PrivateHandler());

	processor->RegisterHandler(
		std::move(transaction_handler));

	PRINT(INFO, MAIN, "\nRun\n");

	processor->Run();//shouldn't return

	PRINT(ERROR, MAIN, "processor Run returned\n");
}

void *start_client_reader(void *dummy)
{
	int retval = server_listener(CLIENT_READER_PORT_NUMBER, 1); // endless loop...
	if (retval < 0)
	{
		PRINT(ERROR, MAIN, "server listener returned %d\n", retval);
		sgx_status_t status = sgx_destroy_enclave(eid);
		if (status != SGX_SUCCESS)
		{
			printf("sgx_destroy_enclave error 0x%x\n", status);
		}
		exit(17);// 17 is the code for automation to detect bind failed and kill old instances of TP
	}
	return NULL;
}

int main(int argc, char **argv)
{
	sgx_status_t status;
	std::string connectString = VALIDATOR_URL_DEFAULT;
	parseArgs(argc, argv, connectString);
	try
	{
		if (load_enclave() != 0)
		{
			printf("load_enclave failed\n");
			return 1;
		}
		
		//start client reader socket server
		pthread_t tid = 0;
		int ret = pthread_create(&tid, NULL, start_client_reader, NULL);
		if (ret != 0)
		{
			printf("pthread_create failed, returned %d", ret);
			status = sgx_destroy_enclave(eid);
			if (status != SGX_SUCCESS)
			{
				printf("sgx_destroy_enclave error 0x%x\n", status);
			}
			return ret;
		}

		//stert TP and listen to txns - never returns
		StartTP(connectString);

		status = sgx_destroy_enclave(eid);
		if (status != SGX_SUCCESS)
		{
			printf("sgx_destroy_enclave error 0x%x\n", status);
		}

		printf("click enter to exit\n");
		getchar();
		return 0;
	}
	catch (std::exception &e)
	{
		PRINT(ERROR, MAIN, "Unexpected exception exiting: %s\n", e.what());
		std::cerr << e.what() << std::endl;
	}
	catch (...)
	{
		PRINT(ERROR, MAIN, "Unexpected exception exiting: unknown type\n");
		std::cerr << "Exiting do to uknown exception." << std::endl;
	}
	return -1;
}