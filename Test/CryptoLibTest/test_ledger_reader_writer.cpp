#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "crypto.h"
#include "crypto_ledger_reader_writer.h"
#include <fstream>
#include <string>
#include <iostream>


TEST(CryptoLib, ledger_reader_writer_set_keys) 
{ 
	Ledger_Reader_Writer reader;
	
    const char* KEY1_PRIV_HEX = "2f1e7b7a130d7ba9da0068b3bb0ba1d79e7e77110302c9f746c3c2a63fe40088";
    private_ec_key_str_t key1_priv_hex;
	memcpy(key1_priv_hex, KEY1_PRIV_HEX, sizeof(private_ec_key_str_t));
	
    const char* KEY1_PUB_HEX = "026a2c795a9776f75464aa3bda3534c3154a6e91b357b1181d3f515110f84b67c5";
	public_ec_key_str_t key1_pub_hex;
	memcpy(key1_pub_hex, KEY1_PUB_HEX, sizeof(public_ec_key_str_t));
	
    const char* KEY3_PRIV_HEX = "51b845323dde22fe646148f0b51eaf5feec8c82ee921d5e0cbe7619f3bb9c64d"; // bad private key
    private_ec_key_str_t key3_priv_hex;
	memcpy(key3_priv_hex, KEY3_PRIV_HEX, sizeof(private_ec_key_str_t));
	
    const char* KEY3_PUB_HEX = "039c20a66b4ec7995391dbec1d8be2c6e6fd63cd259ed5b877cb4e198828c56d"; // bad public key
    public_ec_key_str_t key3_pub_hex;
	memcpy(key3_pub_hex, KEY3_PUB_HEX, sizeof(public_ec_key_str_t));
	
    ASSERT_EQ(reader.set_data_keys(&key1_pub_hex , &key1_priv_hex), true);
    ASSERT_EQ(reader.set_data_keys(NULL, &key1_priv_hex ), false);
    ASSERT_EQ(reader.set_data_keys(&key1_pub_hex, NULL), false);
    ASSERT_EQ(reader.set_data_keys(&key1_pub_hex, &key3_priv_hex), false);
    ASSERT_EQ(reader.set_data_keys(&key3_pub_hex, &key1_priv_hex), false);     
}

TEST(CryptoLib, ledger_reader_writer_full_flow)
{
	bool res = false;
	int retval = 1;
	size_t size = 0;
	uint16_t temp_svn = 0;
	char* request_str = NULL;
	char* response_str = NULL;
	secure_data_content_t* secure_data = NULL;
	ledger_hex_address_t address = {0};
	Ledger_Reader_Writer reader;
	
	private_ec_key_str_t priv_hex;
	public_ec_key_str_t pub_hex;
	
	dh_shared_secret_t dh_shared_secret_in = {};
	dh_shared_secret_t dh_shared_secret_out = {};
	memset(&dh_shared_secret_in, 1, sizeof(dh_shared_secret_t));
	
	Ledger_Reader_Writer nonce_test(0x1234, &dh_shared_secret_in);
	uint64_t nonce = nonce_test.get_nonce();
	ASSERT_EQ(nonce, 0x1234);
	ASSERT_EQ(nonce_test.get_dh_shared_secret(&dh_shared_secret_out), true);
	ASSERT_EQ(memcmp(&dh_shared_secret_in, &dh_shared_secret_out, sizeof(dh_shared_secret_t)), 0);
	
	char* home_dir = getenv("HOME");
	char full_src_name[256];
	char full_dst_name[256];
	char cp_command[512];
	
	memset(address, '0', sizeof(ledger_hex_address_t)-1); // fill with basic 'hex' character
	address[0] = '1';
	address[sizeof(ledger_hex_address_t)-1] = '\0';
			
	const char* KEY1_PRIV_HEX = "a31e74e2ff01281a303c175ff282b888eaf575c08dada6fc2006617f1e36f3ed";
	private_ec_key_str_t key1_priv_hex;
	memcpy(key1_priv_hex, KEY1_PRIV_HEX, sizeof(private_ec_key_str_t));

	const char* KEY1_PUB_HEX = "026e3a6b2f0e66ac22af41b6759ab886458d11595f19280b0458e4decb2148d215";
	public_ec_key_str_t key1_pub_hex;
	memcpy(key1_pub_hex, KEY1_PUB_HEX, sizeof(public_ec_key_str_t));
	
	do
	{
		// save the original ledger file - if it exists
		snprintf(full_src_name, 256, "%s/%s/%s", home_dir, KEYS_DIR_NAME, LEDGER_PUBLIC_SIGN_KEY_FILENAME);
		snprintf(full_dst_name, 256, "%s/%s/%s.backup", home_dir, KEYS_DIR_NAME, LEDGER_PUBLIC_SIGN_KEY_FILENAME);
		snprintf(cp_command, 512, "cp -f %s %s", full_src_name, full_dst_name);
		system(cp_command);
		
		// replace ledger file with client public key
    	std::ofstream out(full_src_name);
    	out << KEY1_PUB_HEX;
    	out.close();

		reader.set_svn(0x0);

		reader.load_keys_from_files();
		reader.set_signing_keys(&key1_pub_hex, &key1_priv_hex);
		
		res = reader.encode_secure_data(address, NULL, 0, TYPE_READER_REQUEST, &request_str);
		if (res == false || request_str == NULL)
		{
			printf("client_encrypt_request failed\n");
			break;
		}
		reader.get_secure_data_svn(request_str, &temp_svn);
		ASSERT_EQ(temp_svn, 0);
					
		res = reader.decode_secure_data(request_str, &secure_data, &size, NULL);
		if (res == false)
		{
			printf("client_decrypt_response failed\n");
			break;
		}
			
		if (secure_data == NULL)
		{
			printf("didn't get the data\n");
			break;
		}
		
		if (memcmp(secure_data->address, address, sizeof(ledger_hex_address_t)) != 0)
		{
			printf("decrypted data is incorrect\n");
			break;
		}
				
		retval = 0;

	} while(0);
	
	// restore the original ledger file - if it exists, and delete the backup
	snprintf(full_src_name, 256, "%s/%s/%s.backup", home_dir, KEYS_DIR_NAME, LEDGER_PUBLIC_SIGN_KEY_FILENAME);
	snprintf(full_dst_name, 256, "%s/%s/%s", home_dir, KEYS_DIR_NAME, LEDGER_PUBLIC_SIGN_KEY_FILENAME);
	snprintf(cp_command, 512, "cp -f %s %s", full_src_name, full_dst_name);
	system(cp_command);
	snprintf(cp_command, 512, "rm -f %s", full_src_name);
	system(cp_command);
		
	if (request_str != NULL) // allocated in reader.encode_secure_data
		free(request_str);
		
	if (response_str != NULL) // allocate in client_exchange_data_with_server
		free(response_str);
		
	if (secure_data != NULL) // allocated in reader.decode_secure_data
		free(secure_data);
	
	ASSERT_EQ (retval, 0);
}
