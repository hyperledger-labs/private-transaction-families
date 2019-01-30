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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#include "app_log.h"
#include "safe_copy.h"
#include "client_network.h"

#define PROXY_CONNCT_REQUEST   "CONNECT %s:%hd HTTP/1.1\r\n\r\n"
#define PROXY_CONNCT_MAX_LEN   1024
#define PROXY_RESPONSE_MAX_LEN 512

// proxy data
#define MAX_PROXY_ADDRESS 1023
char proxy_address[MAX_PROXY_ADDRESS + 1];
uint16_t proxy_port = 0;
bool proxy_set = false;

bool client_set_proxy_server(const char* address, uint16_t port)
{
	if (address == NULL)
		return false;
	
	if (strnlen(address, MAX_PROXY_ADDRESS) > MAX_PROXY_ADDRESS-1)
		return false;
		
	if (safe_strncpy(proxy_address, MAX_PROXY_ADDRESS+1, address, MAX_PROXY_ADDRESS+1) == false)
		return false;
		
	proxy_port = port;
	proxy_set = true;
	
	return true;	
}


static int server_connect(const char *server_url, uint16_t port)
{
	int sockfd = -1;
	int ret = -1;
	struct sockaddr_in server_addr = {};
	struct hostent *server = NULL;
	struct timeval timeout = {};

	server = gethostbyname(server_url);
	if (server == NULL) 
	{
		PRINT(ERROR, CLIENT, "gethostbyname failed\n");
		return -1;
	}
	
	PRINT(INFO, CLIENT, "gethostbyname ok\n");
	
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) 
	{
		PRINT(ERROR, CLIENT,  "socket failed with %d\n", sockfd);
		return -1;
	}
	
	PRINT(INFO, CLIENT, "socket ok\n");
	
	timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) < 0)
    {
		close(sockfd);
		PRINT(ERROR, CLIENT, "setsockopt failed\n");
		return -1;
	}

    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout)) < 0)
    {
		close(sockfd);
		PRINT(ERROR, CLIENT, "setsockopt failed\n");
		return -1;
	}
	
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	if (safe_memcpy((char*)&server_addr.sin_addr.s_addr, sizeof(server_addr.sin_addr.s_addr), (char*)server->h_addr, server->h_length) == false)
	{
		close(sockfd);
		PRINT(ERROR, CLIENT,  "safe_memcpy failed\n");
		return -1;
	}
		
	ret = connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
	if (ret < 0)
	{
		close(sockfd);
		PRINT(ERROR, CLIENT,  "connect failed with %d, errno is %d\n", ret, errno);
		return -1;
	}
		
	return sockfd;
}


int client_connect_to_server(const char *server_url, uint16_t port)
{
	int socket = -1;
	
	if (proxy_set == false)
	{
		socket = server_connect(server_url, port);
		if (socket == -1)
		{
			PRINT(ERROR, CLIENT, "server_connect failed with %d\n", socket);
			return -1;
		}
		
		PRINT(INFO, CLIENT, "server_connect ok\n");
		
		return socket;
	}
	
	// connect thru proxy
		
	char connect_str[PROXY_CONNCT_MAX_LEN] = {0};
	int res = snprintf(connect_str, PROXY_CONNCT_MAX_LEN, PROXY_CONNCT_REQUEST, server_url, port);
	if (res < 0 || res >= PROXY_CONNCT_MAX_LEN)
	{
		PRINT(ERROR, CLIENT, "failed to format proxy connect request, server url might be too long\n");
		return -1;
	}
	
	socket = server_connect(proxy_address, proxy_port);
	if (socket == -1)
	{
		PRINT(ERROR, CLIENT, "proxy server_connect failed with %d\n", socket);
		return -1;
	}
	
	PRINT(INFO, CLIENT, "proxy server_connect ok\n");
		
	ssize_t connect_str_len = strnlen(connect_str, PROXY_CONNCT_MAX_LEN);
	if (send_all(socket, connect_str, connect_str_len) == false)
	{
		PRINT(ERROR, CLIENT, "proxy send_all failed\n");
		client_disconnect_from_server(socket);
		return -1;
	}
	PRINT(INFO, CLIENT, "proxy send:\n%s\n", connect_str);
	
	char proxy_output[PROXY_RESPONSE_MAX_LEN] = {'\0'};
	ssize_t ret = recv(socket, proxy_output, PROXY_RESPONSE_MAX_LEN-1, MSG_NOSIGNAL);
	if (ret < 0 || ret > PROXY_RESPONSE_MAX_LEN - 1)
	{
		PRINT(ERROR, CLIENT, "proxy recv failed with %ld\n", ret);
		client_disconnect_from_server(socket);
		return -1;
	}
	proxy_output[ret] = '\0';
	
	// expexted response is: HTTP/1.1 200 Connection established
	int32_t http_major = 0;
	int32_t http_minor = 0;
	int32_t response_code = 0;
	// banned api - but only scanning integers, not string, so no buffer overflow can happen
	res = sscanf(proxy_output, "HTTP/%d.%d %d", &http_major, &http_minor, &response_code);
	if (res != 3 || response_code < 200 || response_code > 202) // 200 = OK, 201 = CREATED, 202 = ACCEPTED, i think it must be 200, but 201 and 202 also seems ok so...
	{
		PRINT(ERROR, CLIENT, "proxy response is not ok:\n%s\n", proxy_output);
		client_disconnect_from_server(socket);
		return -1;
	}
	
	PRINT(INFO, CLIENT, "proxy response:\n%s\n", proxy_output);
	
	PRINT(INFO, CLIENT, "server_connect ok\n");

	return socket;
}


void client_disconnect_from_server(int sockfd)
{
	if (sockfd != -1)
		close(sockfd);
}


// caller must 'free' the output
int client_exchange_data_with_server(int sockfd, network_packet_t* p_packet, const char* input, char** output)
{
	ssize_t ret = 0;
	char* response_data = NULL;

	if (sockfd == -1 || 
		p_packet == NULL || input == NULL || output == NULL)
	{
		PRINT(ERROR, CLIENT,  "wrong input parameters\n");
		return -1;
	}
	
	assert(p_packet->size < MAX_NETWORK_MSG_SIZE);
	
	if (send_all(sockfd, p_packet, sizeof(network_packet_t)) == false)
	{
		PRINT(ERROR, CLIENT,  "send_all failed\n");
		return -1;
	}
	
	if (send_all(sockfd, input, p_packet->size) == false)
	{
		PRINT(ERROR, CLIENT,  "send_all failed\n");
		return -1;
	}
	
	if (recv_all(sockfd, p_packet, sizeof(network_packet_t)) == false)
	{
		PRINT(ERROR, CLIENT, "recv_all failed\n");
		return -1;
	}

	if (p_packet->size > MAX_NETWORK_MSG_SIZE)
	{
		PRINT(ERROR, CLIENT, "reported message size is %ld bytes, more than expected\n", ret);
		return -1;
	}

	response_data = (char*)malloc(p_packet->size);
	if (response_data == NULL)
	{
		PRINT(ERROR, CLIENT, "malloc failed\n");
		return -1;
	}
		
	if (recv_all(sockfd, response_data, p_packet->size) == false)
	{
		free(response_data);
		PRINT(ERROR, CLIENT, "recv_all failed\n");
		return -1;
	}
	
	*output = response_data;

	return 0;
}
