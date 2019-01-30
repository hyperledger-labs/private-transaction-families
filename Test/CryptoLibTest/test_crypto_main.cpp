#include <gtest/gtest.h>
#include <gmock/gmock.h> 
#include "crypto.h"


TEST(CryptoLib, keys_to_string_negative) 
{
	EC_KEY* test_key = NULL;
	EC_KEY* created_test_key = NULL;
	
	public_ec_key_str_t pub_str;
	private_ec_key_str_t priv_str;
		
	ASSERT_EQ (create_new_ec_key_pair(&test_key), true);
	
	ASSERT_EQ(get_ec_public_key_as_str(NULL, &pub_str), false);
	ASSERT_EQ(get_ec_public_key_as_str(test_key, NULL), false);
	
	ASSERT_EQ(get_ec_private_key_as_str(NULL, &priv_str), false);
	ASSERT_EQ(get_ec_private_key_as_str(test_key, NULL), false);
	
	ASSERT_EQ(get_ec_public_key_as_str(test_key, &pub_str), true);
	ASSERT_EQ(get_ec_private_key_as_str(test_key, &priv_str), true);
	
	ASSERT_EQ(create_public_ec_key_from_str(NULL, &pub_str), false);
	ASSERT_EQ(add_private_ec_key_from_str(NULL, &priv_str), false);
	
	if (test_key != NULL)
		EC_KEY_free(test_key);
}

TEST(CryptoLib, keys_to_string_conversion) 
{
	EC_KEY* test_key = NULL;
	EC_KEY* created_test_key = NULL;
	
	public_ec_key_str_t pub_str;
	private_ec_key_str_t priv_str;
		
	ASSERT_EQ (create_new_ec_key_pair(&test_key), true);
	
	ASSERT_EQ(get_ec_public_key_as_str(test_key, &pub_str), true);
	ASSERT_EQ(get_ec_private_key_as_str(test_key, &priv_str), true);
	
	ASSERT_EQ(create_public_ec_key_from_str(&created_test_key, &pub_str), true);
	ASSERT_EQ(add_private_ec_key_from_str(created_test_key, &priv_str), true);
	
	ASSERT_EQ(EC_POINT_cmp(EC_KEY_get0_group(test_key), EC_KEY_get0_public_key(test_key), EC_KEY_get0_public_key(created_test_key), NULL), 0);
	ASSERT_EQ(BN_cmp(EC_KEY_get0_private_key(test_key), EC_KEY_get0_private_key(created_test_key)), 0);
	
	if (test_key != NULL)
		EC_KEY_free(test_key);
		
	if (created_test_key != NULL)
		EC_KEY_free(created_test_key);
}
