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
 
#ifndef _APP_LOG_H_
#define _APP_LOG_H_

#include <stdio.h>
#include <chrono>

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
#include <ctime>
#include <cstdlib>
#else
#include <time.h>
#endif

#include "log_defines.h"

#include "log4cxx/logger.h"
#include "log4cxx/basicconfigurator.h"
#include "log4cxx/level.h"
#include "log4cxx/patternlayout.h"
#include "log4cxx/fileappender.h"
#include "log4cxx/consoleappender.h"
#include <log4cxx/file.h>
#include <log4cxx/helpers/pool.h>

#define LOG_FILE_NAME "private_tp.log"

using namespace log4cxx;

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger("sawtooth.PrivateLedger"));

void init_log(std::string log_path = "");

#define BUFFER_SIZE 32768
extern __thread char print_buf[BUFFER_SIZE];

#define ADD_TIME(stream)                                                          \
	{                                                                               \
		auto currentTime = std::chrono::system_clock::now();                        \
		auto milli_sec = (currentTime.time_since_epoch().count() / 1000000) % 1000; \
		std::time_t tt = std::chrono::system_clock::to_time_t(currentTime);         \
		auto timeinfo = localtime(&tt);                                             \
		char time_str[100];                                                         \
		strftime(time_str, 100, "%d/%m/%y %H:%M:%S", timeinfo);                     \
		fprintf(stream, "[%s:%03d] ", time_str, (int)milli_sec);                    \
	}

#if defined DEBUG && !defined PERFORMANCE
#define PRINT(level, source, format, ...)                                                                         \
	{                                                                                                             \
		if (level == ERROR || level == INFO)                                                                      \
		{                                                                                                         \
			snprintf(print_buf, BUFFER_SIZE, "(%s:%s) [%s:%d]: " format, source, __FUNCTION__, __FILE__, __LINE__, ##__VA_ARGS__); \
			LOG4CXX_ERROR(logger, print_buf);																	  \
		}                                                                                                         \
		else                                                                                                      \
		{                                                                                                         \
			snprintf(print_buf, BUFFER_SIZE, format, ##__VA_ARGS__);                                              \
			fputs(print_buf, stdout);                                                                             \
		}                                                                                                         \
	}

#else // RELEASE
#define PRINT(level, source, format, ...)                                                                         \
	{                                                                                                             \
		if (level == ERROR)                                                                                       \
		{                                                                                                         \
			snprintf(print_buf, BUFFER_SIZE, "(%s:%s) [%s:%d]: " format, source, __FUNCTION__, __FILE__, __LINE__, ##__VA_ARGS__); \
			LOG4CXX_ERROR(logger, print_buf);																	  \
		}                                                                                                         \
	}
#endif // DEBUG

#endif // _APP_LOG_H_
