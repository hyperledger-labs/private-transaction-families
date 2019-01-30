#include <gtest/gtest.h>
#include <gmock/gmock.h> 
#include "crypto_ledger_reader_writer.h"

const char* KEY1_PRIV_HEX = "2f1e7b7a130d7ba9da0068b3bb0ba1d79e7e77110302c9f746c3c2a63fe40088";
const char* KEY1_PUB_HEX = "026a2c795a9776f75464aa3bda3534c3154a6e91b357b1181d3f515110f84b67c5";

const char* KEY2_PRIV_HEX = "51b845c2cdde22fe646148f0b51eaf5feec8c82ee921d5e0cbe7619f3bb9c62d";
const char* KEY2_PUB_HEX = "039c20a66b4ec7995391dbec1d8bb0e2c6e6fd63cd259ed5b877cb4ea98858cf6d";

const char* KEY3_PRIV_HEX = "51b845323dde22fe646148f0b51eaf5feec8c82ee921d5e0cbe7619f3bb9c64d"; // bad private key
const char* KEY3_PUB_HEX = "039c20a66b4ec7995391dbec1d8be2c6e6fd63cd259ed5b877cb4e198828c56d"; // bad public key
    
EC_KEY* key1 = NULL;
EC_KEY* key2 = NULL;

TEST(CryptoLib, create_public_ec_key_from_str) { 

	public_ec_key_str_t tmp;
	memcpy(tmp, KEY1_PUB_HEX, sizeof(public_ec_key_str_t));
	
	ASSERT_EQ (create_public_ec_key_from_str(&key1, &tmp), true);

}

TEST(CryptoLib, create_public_ec_key_from_str2) { 
    
    public_ec_key_str_t tmp;
	memcpy(tmp, KEY2_PUB_HEX, sizeof(public_ec_key_str_t));
	
    ASSERT_EQ(create_public_ec_key_from_str(&key2, &tmp) , true);

}


TEST(CryptoLib, add_private_ec_key_from_str) { 
  
  private_ec_key_str_t tmp;
  memcpy(tmp, KEY1_PRIV_HEX, sizeof(private_ec_key_str_t));
	
  ASSERT_EQ(add_private_ec_key_from_str(key1, &tmp) , true);
		
}

 
TEST(CryptoLib, add_private_ec_key_from_str2) { 
  
  private_ec_key_str_t tmp;
  memcpy(tmp, KEY2_PRIV_HEX, sizeof(private_ec_key_str_t));
	
  ASSERT_EQ(add_private_ec_key_from_str(key2, &tmp) , true);
		
}


TEST(CryptoLib, create_ec_public_key_from_str) { 
  
  EC_KEY_free(key1);
  
  public_ec_key_str_t tmp;
  memcpy(tmp, KEY3_PUB_HEX, sizeof(public_ec_key_str_t));

  ASSERT_EQ(create_public_ec_key_from_str(&key1, &tmp) , false);
		
}

TEST(CryptoLib, add_private_ec_key_from_str3) { 
  
   private_ec_key_str_t tmp;
   memcpy(tmp, KEY3_PRIV_HEX, sizeof(private_ec_key_str_t));

   ASSERT_EQ(add_private_ec_key_from_str(key2, &tmp), false);

}

static void TearDownTestCase(){
    EC_KEY_free(key1);
    EC_KEY_free(key2);
}
