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

#include <errno.h>

#include "network.h"
#include "app_log.h"

bool send_all(int socket, const void *data, size_t data_size)
{
	size_t sent = 0;
	ssize_t ret = 0;
	uint8_t *bdata = (uint8_t *)data;

	do
	{
		ret = send(socket, &bdata[sent], data_size - sent, MSG_NOSIGNAL);
		if (ret < 0)
		{
			PRINT(ERROR, SERVER, "send failed with %ld, errno %d\n", ret, errno);
			return false;
		}
		if (ret == 0)
			break;
		sent += (size_t)ret;
	} while (sent < data_size);

	if (sent != data_size)
	{
		PRINT(ERROR, SERVER, "send was partial, only %ld of %ld bytes sent\n", sent, data_size);
		return false;
	}

	PRINT(INFO, SERVER, "successfully sent %ld bytes\n", data_size);

	return true;
}

bool recv_all(int socket, void *data, size_t data_size)
{
	size_t received = 0;
	ssize_t ret = 0;
	uint8_t *bdata = (uint8_t *)data;

	do
	{
		ret = recv(socket, &bdata[received], data_size - received, MSG_NOSIGNAL);
		if (ret < 0)
		{
			PRINT(ERROR, SERVER, "recv failed with %ld, errno %d\n", ret, errno);
			return false;
		}
		if (ret == 0)
			break;
		received += (size_t)ret;
	} while (received < data_size);

	if (received != data_size)
	{
		PRINT(ERROR, SERVER, "recv was partial, only %ld of %ld bytes received\n", received, data_size);
		return false;
	}

	PRINT(INFO, SERVER, "successfully received %ld bytes\n", data_size);

	return true;
}
