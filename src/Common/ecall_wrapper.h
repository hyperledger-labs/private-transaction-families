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

#include <utility>
#include <xmmintrin.h>
#include <sgx_error.h>
#include "app_log.h"
#include "Enclave_u.h"

template<typename FUNCTION, typename... ARGS>
auto ecall_wrapper(FUNCTION&& func, ARGS&&... args) -> decltype(func(std::forward<ARGS>(args)...))
{
    sgx_status_t status = SGX_ERROR_UNEXPECTED;
    while (status != SGX_SUCCESS)
    {
        // ecall...
        status = func(args...);
        if (status != SGX_SUCCESS && status != SGX_ERROR_OUT_OF_TCS)
        {// error in the enclave
            // cleanup
            PRINT(ERROR, NONE, "enclave call failed with status 0x%x\n", status);
            return status;
        }
        if (status == SGX_ERROR_OUT_OF_TCS)
            _mm_pause(); // let other threads run
    }
    return status;
}
