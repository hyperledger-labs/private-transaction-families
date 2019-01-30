#include <gtest/gtest.h>
#include <gmock/gmock.h> 
#include "crypto.h"
#include "crypto_enclave.h"
#include <sgx_thread.h>

int threads_equal = 1;

extern "C" int sgx_thread_mutex_lock(sgx_thread_mutex_t *mutex) { return 0; }
extern "C" int sgx_thread_mutex_unlock(sgx_thread_mutex_t *mutex) { return 0; }

extern "C" sgx_thread_t sgx_thread_self(void) { return 1; }
extern "C" int sgx_thread_equal(sgx_thread_t a, sgx_thread_t b) { return threads_equal; }

TEST(CryptoLib, kdf_16bytes)
{
	const char* first_derivation_label = "1234";
	const char* second_derivation_label = "5678";
	kdf_nonce_t kdf_nonce1 = {};
	kdf_nonce_t kdf_nonce2 = {};
	kdf16_key_t session_aes_key = {0};
	
	ASSERT_EQ(derive_16bytes_key_from_double_cmac_aes_128(NULL, kdf_nonce1, second_derivation_label, kdf_nonce2, &session_aes_key), false);
	ASSERT_EQ(derive_16bytes_key_from_double_cmac_aes_128(first_derivation_label, kdf_nonce1, NULL, kdf_nonce2, &session_aes_key), false);
	
	ASSERT_EQ(derive_16bytes_key_from_double_cmac_aes_128(first_derivation_label, kdf_nonce1, second_derivation_label, kdf_nonce2, &session_aes_key), true);
}

TEST(CryptoLib, kdf_ledger_keys)
{
	kdf32_key_t ledger_kds1 = {};
	kdf32_key_t ledger_kds2 = {'\1'};
	ledger_keys_t ledger_keys1 = {};
	ledger_keys_t ledger_keys2 = {};
	ledger_keys_t ledger_keys3 = {};
	ledger_keys_t ledger_keys4 = {};
	
	ASSERT_EQ(generate_ledger_keys_from_kds(ledger_kds1, NULL), false);
	threads_equal = 0;
	ASSERT_EQ(generate_ledger_keys_from_kds(ledger_kds1, &ledger_keys1), false);
	threads_equal = 1;
	
	ASSERT_EQ(generate_ledger_keys_from_kds(ledger_kds1, &ledger_keys1), true);
	ASSERT_EQ(generate_ledger_keys_from_kds(ledger_kds2, &ledger_keys2), true);
	ASSERT_EQ(generate_ledger_keys_from_kds(ledger_kds1, &ledger_keys3), true);
	ASSERT_EQ(generate_ledger_keys_from_kds(ledger_kds2, &ledger_keys4), true);
	
	ASSERT_NE(memcmp(&ledger_keys1, &ledger_keys2, sizeof(ledger_keys_t)), 0);
	ASSERT_EQ(memcmp(&ledger_keys1, &ledger_keys3, sizeof(ledger_keys_t)), 0);
	ASSERT_EQ(memcmp(&ledger_keys2, &ledger_keys4, sizeof(ledger_keys_t)), 0);
}


TEST(CryptoLib, kdf_generate_kds)
{
	kdf32_key_t cur_kds = {};
	kdf32_key_t prev_kds = {};
	
	ASSERT_EQ(generate_previous_svn_kds(NULL, &prev_kds, 1), false);
	ASSERT_EQ(generate_previous_svn_kds(&cur_kds, NULL, 1), false);
	
	ASSERT_EQ(generate_previous_svn_kds(&cur_kds, &prev_kds, 1), true);
	ASSERT_NE(memcmp(cur_kds, prev_kds, sizeof(kdf32_key_t)), 0);
}

TEST(CryptoLib, kdf_generate_aes_siv_key)
{
	kdf32_key_t ledger_kds = {};
	sha256_data_t public_key_hash = {};
	sha256_data_t transaction_nonce_hash = {}; 
	sha256_data_t address_hash = {};
	kdf32_key_t aes_key1 = {};
	kdf32_key_t aes_key2 = {};
	
	ASSERT_EQ(generate_aes_siv_key(&ledger_kds, public_key_hash, transaction_nonce_hash, address_hash, NULL), false);
	
	ASSERT_EQ(generate_aes_siv_key(&ledger_kds, public_key_hash, transaction_nonce_hash, address_hash, &aes_key1), true);
	
	ledger_kds[0] = '\1';
	ASSERT_EQ(generate_aes_siv_key(&ledger_kds, public_key_hash, transaction_nonce_hash, address_hash, &aes_key2), true);
	ASSERT_NE(memcmp(aes_key1, aes_key2, sizeof(kdf32_key_t)), 0);
	ledger_kds[0] = '\0';
	
	public_key_hash[0] = '\1';
	ASSERT_EQ(generate_aes_siv_key(&ledger_kds, public_key_hash, transaction_nonce_hash, address_hash, &aes_key2), true);
	ASSERT_NE(memcmp(aes_key1, aes_key2, sizeof(kdf32_key_t)), 0);
	public_key_hash[0] = '\0';
	
	transaction_nonce_hash[0] = '\1';
	ASSERT_EQ(generate_aes_siv_key(&ledger_kds, public_key_hash, transaction_nonce_hash, address_hash, &aes_key2), true);
	ASSERT_NE(memcmp(aes_key1, aes_key2, sizeof(kdf32_key_t)), 0);
	transaction_nonce_hash[0] = '\0';
	
	address_hash[0] = '\1';
	ASSERT_EQ(generate_aes_siv_key(&ledger_kds, public_key_hash, transaction_nonce_hash, address_hash, &aes_key2), true);
	ASSERT_NE(memcmp(aes_key1, aes_key2, sizeof(kdf32_key_t)), 0);
	address_hash[0] = '\0';
}


TEST(CryptoLib, kdf_32bytes)
{
	const char* first_derivation_label = "1234";
	const char* second_derivation_label = "5678";
	kdf_nonce_t kdf_nonce1 = {};
	kdf_nonce_t kdf_nonce2 = {};
	kdf_record_data_t kdf_record_data = {};
	kdf32_key_t out_key1 = {0};
	kdf32_key_t out_key2 = {0};
	
	ASSERT_EQ(derive_32bytes_key_from_double_hmac_sha_256(NULL, kdf_nonce1, second_derivation_label, kdf_nonce2, NULL, &out_key1), false);
	ASSERT_EQ(derive_32bytes_key_from_double_hmac_sha_256(first_derivation_label, kdf_nonce1, NULL, kdf_nonce2, NULL, &out_key1), false);
	ASSERT_EQ(derive_32bytes_key_from_double_hmac_sha_256(first_derivation_label, kdf_nonce1, second_derivation_label, kdf_nonce2, NULL, NULL), false);
	
	ASSERT_EQ(derive_32bytes_key_from_double_hmac_sha_256(first_derivation_label, kdf_nonce1, second_derivation_label, kdf_nonce2, NULL, &out_key1), true);
	ASSERT_NE(memcmp(out_key1, out_key2, sizeof(kdf32_key_t)), 0);
	
	kdf_record_data.transaction_nonce_hash[0] = '\1'; // otherwise it will remain the same...
	
	ASSERT_EQ(derive_32bytes_key_from_double_hmac_sha_256(first_derivation_label, kdf_nonce1, second_derivation_label, kdf_nonce2, &kdf_record_data, &out_key2), true);
	ASSERT_NE(memcmp(out_key1, out_key2, sizeof(kdf32_key_t)), 0);
}

