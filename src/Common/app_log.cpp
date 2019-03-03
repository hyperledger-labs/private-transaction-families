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
 
 #include "app_log.h"

__thread char print_buf[BUFFER_SIZE] = {'\0'};

void init_log(std::string log_path) {
    PatternLayoutPtr layout(new PatternLayout());
    layout->setConversionPattern(
        LOG4CXX_STR("%d{yyyy-MM-dd HH:mm:ss.SSS} %c - %m"));
    // log4cxx::PatternLayout::setConversionPattern("%d %-5p [%c] - %m%n");
    // console log
    ConsoleAppender *consoleAppender = new ConsoleAppender(layout);
    logger->addAppender(consoleAppender);

    // add logs to file
    if (!log_path.empty()) {
        log4cxx::helpers::Pool p;
        layout->activateOptions(p);
        FileAppenderPtr fileAppender(new FileAppender());
        fileAppender->setFile(log_path + LOG_FILE_NAME);
        fileAppender->setAppend(false);
        fileAppender->setLayout(layout);
        fileAppender->activateOptions(p);
        logger->addAppender(fileAppender);
    }
    Logger::getRootLogger()->setLevel(Level::getAll());
}