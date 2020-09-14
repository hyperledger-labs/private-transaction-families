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

#include "app_log.h"
#include "common.h"
#include "messages.h"
#include "client_network.h"

static __thread uint64_t session_id = 0;
static __thread int ias_socket = -1;

#define SUPPORTED_EXTENDED_EPID_GID 0 // this only marks the type of protocol used, 0 for epid, 1 for ecdsa etc.

int server_process_request(network_packet_t* packet, const char* input_data, char** output_data)
{
	int ret = 0;
	
	if (packet == NULL || input_data == NULL || output_data == NULL)
	{
		PRINT(ERROR, SERVER, "bad input parameters\n");
		return 1;
	}
	
	if (packet->ext_data != SUPPORTED_EXTENDED_EPID_GID) // ext_data is used to pass the extended epid group id
	{
		PRINT(ERROR, SERVER, "extended epid group id 0x%lx is not supported\n", packet->ext_data);
		return 1;
	}
		
	if (packet->type == TYPE_RA_MSG1)
	{
		PRINT(INFO, SERVER, "start processing msg1\n");
    PRINT(INFO, SERVER, "Connecting to " IAS_HOST_ADDRESS " at " IAS_HOST_PORT_STR "\n");
		
		// first, open a channel with IAS
		ias_socket = client_connect_to_server(IAS_HOST_ADDRESS, IAS_HOST_PORT);
		if (ias_socket == -1)
		{
			PRINT(ERROR, SERVER, "failed to connect to IAS\n");
			return 1;
		}

		ret = server_proc_msg1(ias_socket, &session_id, (const sgx_ra_msg1_t*)input_data, packet->size, output_data, &packet->size);
		if (ret != 0)
		{
			PRINT(ERROR, SERVER, "server_proc_msg1 failed with %d\n", ret);
			client_disconnect_from_server(ias_socket); // close connection with ias
			ias_socket = -1;
			return ret;
		}

		packet->type = TYPE_RA_MSG2;
	}
	else if (packet->type == TYPE_RA_MSG3)
	{
		PRINT(INFO, SERVER, "start processing msg3\n");

		ret = server_proc_msg3(session_id, (const sgx_ra_msg3_t*)input_data, packet->size, output_data, &packet->size);
		if (ret != 0)
		{
			PRINT(ERROR, SERVER, "server_proc_msg3 failed with %d\n", ret);
			client_disconnect_from_server(ias_socket); // close connection with ias
			ias_socket = -1;
			return ret;
		}
		
		packet->type = TYPE_RA_MSG4;
		
		client_disconnect_from_server(ias_socket); // close connection with ias
		ias_socket = -1;
		session_id = 0;
	}
	else
	{
		PRINT(ERROR, SERVER, "unknown message type %d\n", packet->type);
		return 1;
	}
	
	PRINT(INFO, SERVER, "finished processing message, sending response\n");
	
	return 0;
}


// using this only in case of an error, otherwise everything is done during normal flow
void server_cleanup_request()
{
	if (session_id != 0)
	{
		server_proc_cleanup(session_id);
		session_id = 0;
	}
	
	if (ias_socket != -1)
	{
		client_disconnect_from_server(ias_socket); // close connection with ias
		ias_socket = -1;
	}
}
