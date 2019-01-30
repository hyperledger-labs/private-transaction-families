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

#ifndef _NETWORK_H_
#define _NETWORK_H_

#include <stdint.h>
#include <netdb.h>

// the port numbers were chosen randomly, only checked they are not in the known port list (https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers)
#define SERVER_SYNC_PORT_NUMBER 36748
#define CLIENT_READER_PORT_NUMBER 36749

#define SERVER_SYNC_SERVER_IP "127.0.0.1"
#define CLIENT_READER_SERVER_IP "127.0.0.1"

#define MAX_MSG_SIZE 1073741824 // 1 GB, equals MAX_NETWORK_MSG_SIZE
// Message types between the client and the server
#define TYPE_RA_MSG1 0x1
#define TYPE_RA_MSG2 0x2
#define TYPE_RA_MSG3 0x3
#define TYPE_RA_MSG4 0x4
#define TYPE_CLIENT_READER 0x5

#pragma pack(1)

typedef struct __network_packet_t
{
	uint16_t type;
	uint16_t padding;
	uint64_t size;	 // size of buffer to follow, not using size_t to be compatible with x86
	uint64_t ext_data; // if needed
} network_packet_t;

#pragma pack()

bool send_all(int socket, const void *data, size_t data_size);
bool recv_all(int socket, void *data, size_t data_size);

#endif //_NETWORK_H_
