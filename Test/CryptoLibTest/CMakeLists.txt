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
PROJECT(TEST_CRYPTOLIB VERSION 1)

SET(files
	${common_dir}/safe_copy.cpp
	${common_dir}/memset_s.c
    ${crypto_dir}/crypto.h
    ${crypto_dir}/crypto.cpp 
    ${crypto_dir}/crypto_transaction.h
    ${crypto_dir}/crypto_ledger_reader_writer.h
    ${crypto_dir}/crypto_ledger_reader_writer.cpp
    ${crypto_dir}/crypto_kdf.cpp
    ${crypto_dir}/crypto_hash.cpp
    ${crypto_dir}/crypto_files.cpp
    ${crypto_dir}/crypto_ecdsa.cpp
    ${crypto_dir}/crypto_aes.cpp
    ${crypto_dir}/crypto_aes_siv.cpp
    ${crypto_dir}/crypto_kdf_enclave.cpp
    ${crypto_dir}/crypto_rand_engine.cpp
    Test.cpp
    test_crypto_dh.cpp
    test_crypto_main.cpp
    test_crypto_hash.cpp
    test_crypto_files.cpp
    test_crypto_kdf.cpp
    test_crypto_aes_siv.cpp
    test_ledger_reader_writer.cpp
)

#Specify directories in which the linker will look for libraries.
link_directories(${crypto_dir}/openssl/lib/)
link_directories(${crypto_dir}/sgxssl/lib64/)

#declare executable
add_executable(${PROJECT_NAME} ${files})

#add include directories
#target_include_directories(${PROJECT_NAME} PUBLIC .)
target_include_directories(${PROJECT_NAME} PUBLIC ${crypto_dir})
target_include_directories(${PROJECT_NAME} PUBLIC ${common_dir})
target_include_directories(${PROJECT_NAME} PUBLIC ${acl_dir})
target_include_directories(${PROJECT_NAME} PUBLIC ${crypto_dir}/openssl/include/)
target_include_directories(${PROJECT_NAME} PUBLIC $ENV{SGX_SDK}/include/)

# need to set DEBUG so it won't call hsm_sign
set_source_files_properties(${crypto_dir}/crypto_ledger_reader_writer.cpp PROPERTIES COMPILE_DEFINITIONS DEBUG)

# Link runTests with what we want to test and the GTest library
target_link_libraries(${PROJECT_NAME} GTest::Main)
target_link_libraries(${PROJECT_NAME} crypto)
target_link_libraries(${PROJECT_NAME} aes_siv)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)


