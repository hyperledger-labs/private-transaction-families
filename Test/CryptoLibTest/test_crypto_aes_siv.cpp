#include <gtest/gtest.h>
#include <gmock/gmock.h> 
#include "crypto_enclave.h"

// test values taken from: https://tools.ietf.org/html/rfc5297

TEST(CryptoLib, aes_siv) 
{ 
	const uint8_t aes_siv_input[14] = { 
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee 
	};
	
	uint8_t aes_siv_output1[30] = {};
	uint8_t aes_siv_output2[14] = {};
		
	const uint8_t aes_siv_expected[30] = {
		0x85, 0x63, 0x2d, 0x07, 0xc6, 0xe8, 0xf3, 0x7f,
		0x95, 0x0a, 0xcd, 0x32, 0x0a, 0x2e, 0xcc, 0x93,
        0x40, 0xc0, 0x2b, 0x96, 0x90, 0xc4, 0xdc, 0x04,
        0xda, 0xef, 0x7f, 0x6a, 0xfe, 0x5c 
    };
		
	const uint8_t aes_siv_key[32] = {
		0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
		0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff 
	};
	
	const uint8_t aes_siv_aad[24] = {
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
	};
	
	ASSERT_EQ (aes_siv_encrypt(NULL, 14, aes_siv_aad, 24, aes_siv_key, 32, aes_siv_output1, 30), false); // input is NULL
	ASSERT_EQ (aes_siv_encrypt(aes_siv_input, 0, aes_siv_aad, 24, aes_siv_key, 32, aes_siv_output1, 30), false); // input size is 0
	ASSERT_EQ (aes_siv_encrypt(aes_siv_input, 14, NULL, 24, aes_siv_key, 32, aes_siv_output1, 30), false); // aad is NULL but aad size is not 0
	ASSERT_EQ (aes_siv_encrypt(aes_siv_input, 14, aes_siv_aad, 24, NULL, 32, aes_siv_output1, 30), false); // key is NULL
	ASSERT_EQ (aes_siv_encrypt(aes_siv_input, 14, aes_siv_aad, 24, aes_siv_key, 64, aes_siv_output1, 30), false); // key size is not 32
	ASSERT_EQ (aes_siv_encrypt(aes_siv_input, 14, aes_siv_aad, 24, aes_siv_key, 32, NULL, 30), false); // output is NULL
	ASSERT_EQ (aes_siv_encrypt(aes_siv_input, 14, aes_siv_aad, 24, aes_siv_key, 32, aes_siv_output1, 32), false); // output size is not input size + 16
	
	ASSERT_EQ (aes_siv_decrypt(NULL, 30, aes_siv_aad, 24, aes_siv_key, 32, aes_siv_output1, 14), false); // input is NULL
	ASSERT_EQ (aes_siv_decrypt(aes_siv_output1, 0, aes_siv_aad, 24, aes_siv_key, 32, aes_siv_output2, 14), false); // input size is 0
	ASSERT_EQ (aes_siv_decrypt(aes_siv_output1, 30, NULL, 24, aes_siv_key, 32, aes_siv_output2, 14), false); // aad is NULL but aad size is not 0
	ASSERT_EQ (aes_siv_decrypt(aes_siv_output1, 30, aes_siv_aad, 24, NULL, 32, aes_siv_output2, 14), false); // key is NULL
	ASSERT_EQ (aes_siv_decrypt(aes_siv_output1, 30, aes_siv_aad, 24, aes_siv_key, 64, aes_siv_output2, 14), false); // key size is not 32
	ASSERT_EQ (aes_siv_decrypt(aes_siv_output1, 30, aes_siv_aad, 24, aes_siv_key, 32, NULL, 14), false); // output is NULL
	ASSERT_EQ (aes_siv_decrypt(aes_siv_output1, 30, aes_siv_aad, 24, aes_siv_key, 32, aes_siv_output2, 32), false); // output size is not input size - 16
	
	ASSERT_EQ (aes_siv_encrypt(aes_siv_input, 14, aes_siv_aad, 24, aes_siv_key, 32, aes_siv_output1, 30), true);
	ASSERT_EQ (memcmp(aes_siv_output1, aes_siv_expected, 30), 0);
	
	ASSERT_EQ (aes_siv_decrypt(aes_siv_output1, 30, aes_siv_aad, 24, aes_siv_key, 32, aes_siv_output2, 14), true);
	ASSERT_EQ (memcmp(aes_siv_output2, aes_siv_input, 14), 0);
}
