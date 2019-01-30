///////////////////////////////////////////////////////
// mock of ACL code
///////////////////////////////////////////////////////
#include "Enclave_t.h"
#include <unordered_map>
#include <iostream>
#include <cstring>

namespace
{
std::unordered_map<std::string, std::string> dataMock;
}
sgx_status_t SGX_CDECL tl_call_stl_read(int* retval, uint32_t* id, const char* addr, char* value, uint32_t data_size)
{

    // Declare an iterator to unordered_map
    // std::unordered_map<std::string, std::string>::iterator it;

    // Find if an element with key "First" exists or not.
    // find() returns an iterator
    auto it = dataMock.find(addr);

    // Check if iterator points to end of map
    if (it != dataMock.end())
    {
        auto length = it->second.size();
        if (data_size == 0)
        {
            *retval = length;
        }
        else if (data_size < length)
        {
            *retval = -1;
        }
        else
        {
            it->second.copy(value, length);
            value[length] = '\0';
            *retval = length;
        }

        // std::cout << "read the value : " << value <<std::endl;
    }
    else
    {
        value = (char *)"";

        std::cout << "cant find read address\n";
        *retval =  0;
    }
}

sgx_status_t SGX_CDECL tl_call_stl_read_prefix(int* retval, uint32_t* id, const char* addr_prefix, char* value, uint32_t num_of_addr)
{
    
}

sgx_status_t SGX_CDECL tl_call_stl_read_cr(int* retval, uint32_t* id, const char* addr, char* value, uint32_t data_size)
{
    // Find if an element with key "First" exists or not.
    // find() returns an iterator
    auto it = dataMock.find(addr);

    // Check if iterator points to end of map
    if (it != dataMock.end())
    {
        it->second.copy(value, 0, data_size);

        // std::cout << "read the value : " << value <<std::endl;
    }
    else
    {
        std::cout << "cant find\n";
    }

    *retval = data_size;
}
sgx_status_t SGX_CDECL tl_call_stl_write(sgx_status_t* retval, const char* addr, const char* value, size_t data_size)
{

    std::string val(value);
    std::string address(addr);
    if (dataMock.count(address) > 0)
    {
        dataMock.erase(address);
    }
    dataMock.insert({address, val});
    //std::cout << "insert to address: " << addr <<" value : " << val << std::endl;
    *retval =  SGX_SUCCESS;
}
sgx_status_t SGX_CDECL tl_call_stl_delete(sgx_status_t* retval, const char* addresses, size_t num_of_address)
{
    *retval =  SGX_SUCCESS;
}

bool deleteAllValues()
{
    std::cout << "delete : " << std::endl;
    for(auto it = dataMock.begin(); it != dataMock.end(); ++it)
    {
        it->second = "";

        std::cout << "delete : " << it->second << std::endl;
    }
    return true;
}