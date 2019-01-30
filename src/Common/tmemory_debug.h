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
 
 // this file is used for memory debug and only have effect in DEBUG mode
#ifdef MEM_DEBUG
#include <openssl/crypto.h>

#define malloc(num) 		OPENSSL_malloc(num)
#define realloc(addr, num) 	OPENSSL_realloc(addr, num)
#define free(addr) 			OPENSSL_free(addr)

#endif // DEBUG
