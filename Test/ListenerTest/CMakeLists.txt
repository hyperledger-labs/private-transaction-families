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
PROJECT(TEST_LISTENER VERSION 1)

SET(files
    ${listener_app_dir}/data_map.cpp 
    ${listener_app_dir}/listener_ocalls.cpp
    ${listener_app_dir}/rest_handler.cpp
    ${common_dir}/PrivateLedger.cpp
    ${common_dir}/app_log.cpp
    ${main_app_dir}/Enclave_u.h
    Test_listener.cpp
)
# set properties for sgx generated file
set_source_files_properties( ${main_app_dir}/Enclave_u.h PROPERTIES GENERATED TRUE )

#declare executable 
add_executable(${PROJECT_NAME} ${files})

# add dependency on sgx generated files
add_dependencies(${PROJECT_NAME} generate-enclave-u)

#add include directories, listener is using sgx and sawtooth.h

target_include_directories(${PROJECT_NAME} PUBLIC $ENV{SGX_SDK}/include/)
target_include_directories(${PROJECT_NAME} PUBLIC ${common_dir})
target_include_directories(${PROJECT_NAME} PUBLIC ${listener_app_dir})
target_include_directories(${PROJECT_NAME} PUBLIC ${main_app_dir})
target_include_directories(${PROJECT_NAME} PUBLIC ${listener_app_dir}/../../../sawtooth-sdk-cxx/include/)
#listener is using curl lib
target_link_libraries(${PROJECT_NAME} curl)
find_package(Protobuf REQUIRED)
target_link_libraries(${PROJECT_NAME} protobuf)

# Link runTests with what we want to test and the GTest library
target_link_libraries(${PROJECT_NAME} GTest::Main)

target_link_libraries(${PROJECT_NAME} log4cxx)


set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)


