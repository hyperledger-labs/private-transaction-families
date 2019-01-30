#include <gtest/gtest.h>
#include <gmock/gmock.h> 
#include "crypto.h"

TEST(CryptoLib, keys_files_negative) 
{
	EC_KEY* test_key = NULL;
	EC_KEY* loaded_test_key = NULL;
	
	ASSERT_EQ (create_new_ec_key_pair(NULL), false);
	
	ASSERT_EQ (create_new_ec_key_pair(&test_key), true);
	
	ASSERT_EQ(save_public_ec_key_to_file(NULL, "public_test_key.hex"), false);
	ASSERT_EQ(save_public_ec_key_to_file(test_key, NULL), false);
	
	ASSERT_EQ(save_public_ec_key_to_file(test_key, "public_test_key.hex"), true);
	
	ASSERT_EQ(save_private_ec_key_to_file(NULL, "private_test_key.hex"), false);
	ASSERT_EQ(save_private_ec_key_to_file(test_key, NULL), false);
	
	ASSERT_EQ(load_public_ec_key_from_file(NULL, "public_test_key.hex"), false);
	ASSERT_EQ(load_public_ec_key_from_file(&loaded_test_key, NULL), false);
		
	ASSERT_EQ(load_public_ec_key_from_file(&loaded_test_key, "public_test_key.hex"), true);
	
	ASSERT_EQ(add_private_ec_key_from_file(NULL, "private_test_key.hex"), false);
	ASSERT_EQ(add_private_ec_key_from_file(loaded_test_key, NULL), false);
	
	if (test_key != NULL)
		EC_KEY_free(test_key);
		
	if (loaded_test_key != NULL)
		EC_KEY_free(loaded_test_key);
}


TEST(CryptoLib, keys_files) 
{
	EC_KEY* test_key = NULL;
	EC_KEY* loaded_test_key = NULL;
	
	ASSERT_EQ (create_new_ec_key_pair(&test_key), true);
	
	ASSERT_EQ(save_public_ec_key_to_file(test_key, "public_test_key.hex"), true);
	ASSERT_EQ(save_private_ec_key_to_file(test_key, "private_test_key.hex"), true);
	
	ASSERT_EQ(load_public_ec_key_from_file(&loaded_test_key, "public_test_key.hex"), true);
	ASSERT_EQ(add_private_ec_key_from_file(loaded_test_key, "private_test_key.hex"), true);
	
	ASSERT_EQ(EC_POINT_cmp(EC_KEY_get0_group(test_key), EC_KEY_get0_public_key(test_key), EC_KEY_get0_public_key(loaded_test_key), NULL), 0);
	ASSERT_EQ(BN_cmp(EC_KEY_get0_private_key(test_key), EC_KEY_get0_private_key(loaded_test_key)), 0);
	
	if (test_key != NULL)
		EC_KEY_free(test_key);
		
	if (loaded_test_key != NULL)
		EC_KEY_free(loaded_test_key);
}
