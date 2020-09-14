///////////////////////////////////////////////////////
// mock of sawtooth
///////////////////////////////////////////////////////
#include "sawtooth_sdk.h"

namespace
{
std::unordered_map<std::string, std::string> dataMock;
}

class SawtoothStateMock : public sawtooth::GlobalState
{
  public:
    SawtoothStateMock() {}
    virtual ~SawtoothStateMock() {}

    virtual bool GetState(std::string *out_value, const std::string &address) const
    {
        *out_value = "";
        auto it = dataMock.find(address);
        if (it != dataMock.end())
        {
            *out_value = it->second;
        }
        return true;
    }

    virtual void SetState(const std::string &address, const std::string &value) const
    {
        if (dataMock.count(address) > 0)
        {
            dataMock.erase(address);
        }
        dataMock.insert({address, value});
    }

    virtual void DeleteState(const std::vector<std::string> &address) const
    {
        for (const auto addr : address)
        {
            dataMock.erase(addr);
        }
    }

    virtual void GetState(std::unordered_map<std::string, std::string>* out_values,
        const std::vector<std::string>& addresses) const {}
    virtual void SetState(const std::vector<KeyValue>& addresses) const {}
    virtual void DeleteState(const std::string& address) const {}
    virtual void ListAddresses(std::vector<std::string>* out_values,
    		const std::string& address) const {}
    virtual void ListAddresses(std::vector<std::string>* out_values,
    		const std::vector<std::string>& address) const {}
    virtual void AddEvent(const std::string& event_type, const std::vector<KeyValue>& kv_pairs, const std::string& event_data) const {}
};

bool deleteAllValues()
{
    std::cout << "delete : " << std::endl;
    for (auto it = dataMock.begin(); it != dataMock.end(); ++it)
    {
        it->second = "";

        std::cout << "delete : " << it->second << std::endl;
    }
    return true;
}
