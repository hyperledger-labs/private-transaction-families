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
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h> // for inet_ntoa

#include "app_log.h"
#include "safe_copy.h"

#include "server_network.h"

typedef struct _thread_data_t
{
	int sockfd;
	struct in_addr addr;
	uint32_t iterations;
} thread_data_t;


static void* process_client_request(void* _thread_data)
{
	ssize_t ret = 0;
	uint32_t i = 0;
	network_packet_t packet = {};
	char* input_data = NULL;
	char* output_data = NULL;
	thread_data_t* thread_data = (thread_data_t*)_thread_data;
	
	int res = pthread_detach(pthread_self());
	if (res != 0) // this will lead to resource leakage and eventually new threads can't be created, but nothing to do about it so keep running
	{
		PRINT(ERROR, SERVER, "pthread_detach failed with %d\n", res);
	}
	
	try {
		char* client_addr = inet_ntoa(thread_data->addr); // returns pointer to a per-thread static buffer, used for debug prints
		
		for (i = 0 ; i < thread_data->iterations ; i++)
		{
		
			if (recv_all(thread_data->sockfd, &packet, sizeof(network_packet_t)) == false)
			{
				PRINT(ERROR, SERVER, "recv_all from %s failed\n", client_addr);
				break;
			}
			
			if (packet.size >= MAX_NETWORK_MSG_SIZE)
			{
				PRINT(ERROR, SERVER, "packet size is too big\n");
				break;
			}
			
			input_data = (char*)malloc(packet.size);
			if (input_data == NULL)
			{
				PRINT(ERROR, SERVER, "malloc failed\n");
				break;
			}
			
			if (recv_all(thread_data->sockfd, input_data, packet.size) == false)
			{
				PRINT(ERROR, SERVER, "recv_all from %s failed\n", client_addr);
				break;
			}
			
			PRINT(INFO, SERVER, "received %ld bytes from %s\n", packet.size, client_addr);

			ret = server_process_request(&packet, input_data, &output_data); // this function 'malloc' output_data so it must be freed
			if (ret != 0)
			{
				PRINT(ERROR, SERVER, "client_reader_proc_request from %s failed with %ld\n", client_addr, ret);
				break;
			}
				
			PRINT(INFO, SERVER, "finished processing client request, sending response\n");
			
			if (send_all(thread_data->sockfd, &packet, sizeof(network_packet_t)) == false)
			{
				PRINT(ERROR, SERVER, "send_all to %s failed\n", client_addr);
				break;
			}

			if (packet.size > 0)
			{
				if (send_all(thread_data->sockfd, output_data, packet.size) == false)
				{
					PRINT(ERROR, SERVER, "send_all to %s failed\n", client_addr);
					break;
				}
					
				PRINT(INFO, SERVER, "sent %ld bytes to %s\n", packet.size, client_addr);			
			}
			else
			{
				PRINT(ERROR, SERVER, "error packet.size %ld-  is not grater than 0\n", packet.size);			
			}
			
			if (input_data != NULL)
			{
				free(input_data);
				input_data = NULL;
			}
			
			if (output_data != NULL)
			{
				free(output_data);
				output_data = NULL;
			}
		}
				
		if (i == thread_data->iterations)
		{
			PRINT(INFO, SERVER, "session with %s finished successfully!\n", client_addr);
		}
		else
		{
			PRINT(ERROR, SERVER, "session with %s finished with error!\n", client_addr);
		}
	}
	catch (...)
	{
		PRINT(ERROR, SERVER, "process_client_request failed, exception was thrown!\n");
	}
	
	server_cleanup_request();
	
	if (input_data != NULL)
		free(input_data);
		
	if (output_data != NULL)
		free(output_data);
	
	close(thread_data->sockfd); // close connection with the client

	free(thread_data);
	
	return NULL;
}


// the server socket
static int sockfd = -1;

bool exit_thread = false;

static void close_socket(int sig, siginfo_t *siginfo, void *context)
{
	(void)sig;
	(void)siginfo;
	(void)context;
	
	exit_thread = true;
	
	if (sockfd >= 0)
	{
		close(sockfd);
		sockfd = -1;
	}
	
	PRINT(INFO, SERVER, "listening socket is closed, server exiting!\n");
//	exit(0); let the program finish, don't kill it
}

// this function initializes the server and waits for incoming connections
// port - port number to listen on
// iterations - number of times to receive messages and send responses for each client
int server_listener(uint16_t port, uint32_t iterations)
{
	int ret = -1;
	struct sockaddr_in server_addr = {};
	
/* register signal handler for socket cleanup when exiting the endless loop, this is not a must, 
 * but if not done, then it takes a few seconds until the system closes it */
	struct sigaction action = {};
 
	action.sa_sigaction = &close_socket;
	action.sa_flags = SA_SIGINFO;
 
	ret = sigaction(SIGINT, &action, NULL);
	if (ret < 0) 
	{
		PRINT(ERROR, SERVER, "sigaction failed with %d\n", ret);
		return 1;
	}
	
	exit_thread = false;

/* create a socket and start listening */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) 
	{
		PRINT(ERROR, SERVER, "socket failed with %d\n", sockfd);
		return -1;
	}
	
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(port);
	
	ret = bind(sockfd, (struct sockaddr*)&server_addr, sizeof(struct sockaddr_in));
	if (ret < 0)
	{
		close(sockfd);
		PRINT(ERROR, SERVER, "bind failed with %d\n", ret);
		return ret;
	}

	listen(sockfd, 3);
	
	PRINT(INFO, SERVER, "waiting for remote connections...\n");
	
	while (true)
	{
		int newsockfd = -1;
		struct sockaddr_in client_addr = {};
		socklen_t client_adder_len = sizeof(struct sockaddr_in);
		
		newsockfd = accept(sockfd, (struct sockaddr*)&client_addr, &client_adder_len);
		if (newsockfd < 0) 
		{
			if (exit_thread == true)
				break;

			PRINT(ERROR, SERVER, "accept failed with %d\n", newsockfd);
			continue;
		}
		
		PRINT(INFO, SERVER, "creating new thread for serving the read request from %s\n", inet_ntoa(client_addr.sin_addr));
		
		thread_data_t* thread_data = (thread_data_t*)malloc(sizeof(thread_data_t));
		if (thread_data == NULL)
		{
			close(newsockfd);
			PRINT(ERROR, SERVER, "malloc failed\n");
			continue;
		}
		
		thread_data->sockfd = newsockfd;
		thread_data->addr = client_addr.sin_addr;
		thread_data->iterations = iterations;
		
		pthread_t tid = 0;
		ret = pthread_create(&tid, NULL, process_client_request, (void*)thread_data);
		if (ret != 0)
		{
			close(newsockfd);
			free(thread_data);
			PRINT(ERROR, SERVER, "pthread_create failed with %d\n", ret);
			continue;
		}
	}
	
	if (sockfd != -1)
		close(sockfd);
		
	return 0;
}

