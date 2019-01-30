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
 
 #ifndef _CLIENT_NETWORK_H_
#define _CLIENT_NETWORK_H_

#include "network.h"

bool client_set_proxy_server(const char* address, uint16_t port);
int  client_connect_to_server(const char *server_url, uint16_t port);
void client_disconnect_from_server(int sockfd);
int  client_exchange_data_with_server(int sockfd, network_packet_t* p_packet, const char* input, char** output); // p_packet is an in-out parameter

#endif //_CLIENT_NETWORK_H_
