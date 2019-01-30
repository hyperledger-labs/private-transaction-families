#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "businessLogic.h"

TEST(Busineess_logic, payloadToParams_sample) { 
    std::string verb;
    std::string name;
    int value;
    //TODO test random values and corner cases
    secure::string payload = "{\"Verb\": \"inc\", \"Name\": \"Test\", \"Value\": 1}";
    business_logic::payloadToParams(payload, verb, name, value);
    
    ASSERT_EQ(verb, "inc");
    ASSERT_EQ(name, "Test");
    ASSERT_EQ(value, 1);
}


