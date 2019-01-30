# Copyright 2017 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#------------------------------------------------------------------------------
PROJECT(TEST_BL VERSION 1)

SET(files
    Test.cpp
    ${business_logic_dir}/businessLogic.h 
    ${business_logic_dir}/cJSON.h
    ${business_logic_dir}/businessLogic.cpp
    ${common_dir}/PrivateLedger.h
    ${common_dir}/PrivateLedger.cpp
    ${business_logic_dir}/cJSON.c
    mock_acl.cpp
    mock_crypto.cpp
)
#declare executable 
add_executable(${PROJECT_NAME} ${files})

target_include_directories(${PROJECT_NAME} PUBLIC ${common_dir})
target_include_directories(${PROJECT_NAME} PUBLIC ${business_logic_dir})
target_include_directories(${PROJECT_NAME} PUBLIC ${acl_dir})
target_include_directories(${PROJECT_NAME} PUBLIC ${crypto_dir})


# Link runTests with what we want to test and the GTest library
target_link_libraries(${PROJECT_NAME} GTest::Main)


set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)


