#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "data_map.h"
#include "rest_handler.h"
#include "Enclave_u.h"
#include "mock_sawtooth.h"
#include "config.h"
#include "txn_handler.h"

//declare the extern global
std::string config::g_key_path;
std::string config::g_rest_url;
std::string addr1, addr2, addr3;
namespace txn_handler
{
sawtooth::GlobalStateUPtr contextPtr;
}

using namespace listener;
void set_sawtooth_mock()
{
    std::unique_ptr<SawtoothStateMock> mock_ctx_uptr(new SawtoothStateMock);
    txn_handler::contextPtr = std::move(mock_ctx_uptr);
}

void SetUpListener()
{
    set_sawtooth_mock();
    std::array<uint8_t, ADDRESS_LENGTH / 2> addr_bytes = {};
    std::iota(std::begin(addr_bytes), std::end(addr_bytes), 13);
    addr1 = ToHexString(addr_bytes.data(), addr_bytes.size()).c_str();
    std::iota(std::begin(addr_bytes), std::end(addr_bytes), 25);
    addr2 = ToHexString(addr_bytes.data(), addr_bytes.size()).c_str();
    std::iota(std::begin(addr_bytes), std::end(addr_bytes), 41);
    addr3 = ToHexString(addr_bytes.data(), addr_bytes.size()).c_str();
}

TEST(Listener, tl_call_stl_write)
{
    std::string str = "mock value in addr1";
    ASSERT_EQ(tl_call_stl_write(addr1.c_str(), str.c_str(), str.size() + 1), 0);
}

TEST(Listener, tl_call_stl_read)
{
    uint32_t id;
    std::vector<char> value = {};
    std::string res_str = "mock value in addr1";
    int res_len = tl_call_stl_read(&id, addr1.c_str(), value.data(), 0);
    ASSERT_EQ(res_len, res_str.size() + 1);
    value.reserve(res_len);
    res_len = tl_call_stl_read(&id, addr1.c_str(), value.data(), res_len);
    ASSERT_EQ(res_len, res_str.size() + 1);
    ASSERT_EQ(std::string(std::begin(value), std::begin(value) + res_len - 1), res_str.c_str());
    // read again should return empty string
    res_len = tl_call_stl_read(&id, addr1.c_str(), value.data(), res_len);
    ASSERT_EQ(res_len, 0);
}

TEST(Listener, tl_call_stl_delete)
{
    ASSERT_EQ(tl_call_stl_delete(addr1.c_str(), 1), 0);
    uint32_t id;
    std::vector<char> value = {};
    int res_len = tl_call_stl_read(&id, addr1.c_str(), value.data(), 0);
    ASSERT_EQ(res_len, 0);
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    SetUpListener();
    auto ret = RUN_ALL_TESTS();
    deleteAllValues();
    return ret;
}
