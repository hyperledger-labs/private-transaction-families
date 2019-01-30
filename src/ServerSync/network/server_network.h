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
 
#ifndef _SERVER_NETWORK_H_
#define _SERVER_NETWORK_H_

#include "network.h"

// this function initializes the server and waits (forever) for incoming connections
// port - port number to listen on
// iterations - number of times to receive message and send response for each client
int server_listener(uint16_t port, uint32_t iterations);

// these functions are implemented in the specific server code
int server_process_request(network_packet_t* packet, const char* input_data, char** output_data); // p_packet is an in-out parameter
void server_cleanup_request(); // called when the session is over

#endif // _SERVER_NETWORK_H_
