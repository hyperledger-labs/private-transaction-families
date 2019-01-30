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
#include <limits.h>
#include <errno.h>

#include "parse_string.h"

bool str_to_uint16(char* str, uint16_t* out)
{
	char* endptr = NULL;
	long num = 0;
	
	if (str == NULL)
		return false;
	
	num = strtol(str, &endptr, 10);
	if (num <= 0) // uint16 is positive
		return false;
	
	if (num == LONG_MAX || num == LONG_MIN)
		if (errno == ERANGE)
			return false;
			
	if (num > USHRT_MAX)
		return false;
		
	*out = (uint16_t)(num & USHRT_MAX);
	return true;
}
