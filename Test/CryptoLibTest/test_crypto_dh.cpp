#include <gtest/gtest.h>
#include <gmock/gmock.h> 
#include "crypto.h"


TEST(CryptoLib, dh_negative)
{
	EC_KEY* test_key1 = NULL;
	
	dh_shared_secret_t dh_secret1;
	
	ASSERT_EQ (create_new_ec_key_pair(&test_key1), true);
	
	ASSERT_EQ(calculate_dh_shared_secret(test_key1, NULL, &dh_secret1), false);
	ASSERT_EQ(calculate_dh_shared_secret(NULL, test_key1, &dh_secret1), false);
	ASSERT_EQ(calculate_dh_shared_secret(test_key1, test_key1, NULL), false);
	
	if (test_key1 != NULL)
		EC_KEY_free(test_key1);
}

 
TEST(CryptoLib, dh_derivation_direct) 
{
	EC_KEY* test_key1 = NULL;
	EC_KEY* test_key2 = NULL;
	
	dh_shared_secret_t dh_secret1;
	dh_shared_secret_t dh_secret2;
	
	ASSERT_EQ (create_new_ec_key_pair(&test_key1), true);
	ASSERT_EQ (create_new_ec_key_pair(&test_key2), true);
	
	ASSERT_EQ(calculate_dh_shared_secret(test_key1, test_key2, &dh_secret1), true);
	ASSERT_EQ(calculate_dh_shared_secret(test_key2, test_key1, &dh_secret2), true);
	
	ASSERT_EQ(memcmp(dh_secret1, dh_secret2, sizeof(dh_shared_secret_t)), 0);
		
	if (test_key1 != NULL)
		EC_KEY_free(test_key1);
		
	if (test_key2 != NULL)
		EC_KEY_free(test_key2);
}


TEST(CryptoLib, dh_derivation_strings) 
{
	EC_KEY* test_key1 = NULL;
	EC_KEY* test_key2 = NULL;
	
	public_ec_key_str_t pub_str;
	private_ec_key_str_t priv_str;
	
	dh_shared_secret_t dh_secret1;
	dh_shared_secret_t dh_secret2;
		
	ASSERT_EQ (create_new_ec_key_pair(&test_key1), true);
	ASSERT_EQ (create_new_ec_key_pair(&test_key2), true);
	
	ASSERT_EQ(get_ec_public_key_as_str(test_key1, &pub_str), true);
	ASSERT_EQ(get_ec_private_key_as_str(test_key2, &priv_str), true);
	
	ASSERT_EQ(calculate_dh_shared_secret(test_key1, test_key2, &dh_secret1), true);
	ASSERT_EQ(calculate_dh_shared_secret(test_key2, test_key1, &dh_secret2), true);
	
	ASSERT_EQ(memcmp(dh_secret1, dh_secret2, sizeof(dh_shared_secret_t)), 0);
		
	if (test_key1 != NULL)
		EC_KEY_free(test_key1);
		
	if (test_key2 != NULL)
		EC_KEY_free(test_key2);
}

