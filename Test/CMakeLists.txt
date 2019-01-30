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
cmake_minimum_required (VERSION 3.5)
set (CMAKE_CXX_STANDARD 11)

# Locate GTest
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})
include_directories(${GMOCK_INCLUDE_DIRS})

#code coverage flags
SET(GCC_COVERAGE_COMPILE_FLAGS "-g -O0 -coverage -fprofile-arcs -ftest-coverage")
SET(GCC_COVERAGE_LINK_FLAGS    "-coverage -lgcov")
SET( CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS}" )
SET( CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS}" )
SET( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}" )

# common directories to be used by sub directories cmake
SET(business_logic_dir ${CMAKE_CURRENT_SOURCE_DIR}/../src/BusinessLogic)
SET(common_dir ${CMAKE_CURRENT_SOURCE_DIR}/../src/Common)
SET(listener_app_dir ${CMAKE_CURRENT_SOURCE_DIR}/../src/Listener/App)
SET(main_app_dir ${CMAKE_CURRENT_SOURCE_DIR}/../src/Main/App)
SET(listener_enclave_dir ${CMAKE_CURRENT_SOURCE_DIR}/../src/Listener/Enclave)
SET(main_enclave_dir ${CMAKE_CURRENT_SOURCE_DIR}/../src/Main/Enclave)
SET(acl_dir ${CMAKE_CURRENT_SOURCE_DIR}/../src/AccessControlLogic)
SET(crypto_dir ${CMAKE_CURRENT_SOURCE_DIR}/../src/CryptoLib)
SET(network_dir ${CMAKE_CURRENT_SOURCE_DIR}/../src/Network)

# run edger8r to create sgx generated files
add_custom_target(generate-enclave-t
                  COMMAND make -C . -f generate_edge_files_t.mk 
                  WORKING_DIRECTORY ${main_enclave_dir} )
add_custom_target(generate-enclave-u
                  COMMAND make -C . -f generate_edge_files_u.mk 
                  WORKING_DIRECTORY ${main_app_dir} )

# add each subdirectory tests
add_subdirectory(ListenerTest)
add_subdirectory(CryptoLibTest)
add_subdirectory(AccessControlLogicTest)
