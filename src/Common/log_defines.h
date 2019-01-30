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
 
#ifndef _LOG_DEFINES_H_
#define _LOG_DEFINES_H_

#define MAIN    "main"
#define GENESIS "genesis"
#define CLIENT  "client"
#define SERVER  "server"
#define IAS     "ias-connection"
#define OCALL   "ocall"
#define CRYPTO	"crypto"
#define LISTENER    "listener"
#define LOGIC   "buiness-logic"
#define ACL_LOG   "ACL"
#define COMMON   "common"
#define NONE    ""

#define ERROR 1 // prints to stderr, also in release mode, includes time, filename and line
#define INFO  2 // prints to stdout, only in debug mode, includes time
#define PLAIN 3 // prints to stdout, only in debug mode, no time

#endif // _LOG_DEFINES_H_
