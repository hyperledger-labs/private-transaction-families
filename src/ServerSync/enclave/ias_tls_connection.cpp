/*
* Copyright 2018 Intel Corporation
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
 
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <cJSON.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "enclave_log.h"
#include "ias_session.h"
#include "common.h"
#include "ledger_keys.h"
#include "tmemory_debug.h" // only have effect in DEBUG mode

#include "Enclave_t.h"

// this function is implemented in sgxssl which is linked with this enclave
extern "C" int sgxssl_sscanf(const char *str, const char *fmt, ...);

// these values are only needed because strlen is banned and we need to define max lengths for strnlen function
#define MAXLEN_FIXED_STRING 		128
#define MAXLEN_SIGNATURE_STRING 	1024 // usually less then 400
#define MINLEN_SIGNATURE_STRING 	50 // usually less then 400
#define MAXLEN_CERTIFICATE_STRING 	8192 // usually less then 4000 
#define MINLEN_CERTIFICATE_STRING 	100 // usually less then 4000 
#define MAXLEN_CONTENT_STRING 		8192 // usually less then 3000


#define ATTEST_REQUEST	"GET https://" IAS_HOST_ADDRESS ":" IAS_HOST_PORT_STR "/attestation/sgx/v3/sigrl/%08x HTTP/1.1\r\n\r\n"
#define REPORT_REQUEST	"POST https://" IAS_HOST_ADDRESS ":" IAS_HOST_PORT_STR "/attestation/sgx/v3/report HTTP/1.1\r\ncontent-type: application/json\r\ncontent-length: %d\r\n\r\n%s"

#define IAS_RESPONSE_MAX_LEN (32*ONE_KB)

// hard coded IAS certificates
extern char ias_ca_cert_buffer[];
extern char attestation_ca_cert_buffer[];

#define QUOTE_STRINGS_COUNT 8
const char* quote_status_strings[QUOTE_STRINGS_COUNT] = {
	"OK",
	"SIGNATURE_INVALID",
	"GROUP_REVOKED",
	"SIGNATURE_REVOKED",
	"KEY_REVOKED",
	"SIGRL_VERSION_MISMATCH",
	"GROUP_OUT_OF_DATE",
	"CONFIGURATION_NEEDED"
};

#define PSE_STRINGS_COUNT 6
const char* pse_status_strings[PSE_STRINGS_COUNT] = {
	"OK",
	"UNKNOWN",
	"INVALID",
	"OUT_OF_DATE",
	"REVOKED",
	"RL_VERSION_MISMATCH"
};

// use this for debugging the certificate chain, can also change the result to 1 if the root CA is not present (Google test)
/*
static int custom_verify_peer(int preverify_ok, X509_STORE_CTX* ctx) 
{
	PRINT(INFO, IAS, "custom_verify_peer called, preverify_ok=%d\n", preverify_ok);
	
	X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
	if (cert == NULL)
	{
		PRINT(ERROR, IAS, "X509_STORE_CTX_get_current_cert returned NULL\n");
		return 0; // error
	}
	
	char* name = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
	PRINT(INFO, IAS, "issuer name: %s\n", name);
	free(name);
		
	char* subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
	PRINT(INFO, IAS, "subject name: %s\n", subject);
	free(subject);
	
	return preverify_ok; // don't change the value, not doing any actual checks here...
}
*/

static void print_certificate_details(X509* cert)
{
	BIO* mem = BIO_new(BIO_s_mem());
	if (mem == NULL)
		return;
	
	X509_print_ex(mem, cert, XN_FLAG_COMPAT, X509_FLAG_COMPAT | X509_FLAG_NO_PUBKEY | X509_FLAG_NO_SIGDUMP);
	BIO_puts(mem, ""); // terminate the string
	
	char* data  = NULL;
	BIO_get_mem_data(mem, &data);
	
	PRINT(INFO, IAS, "%s\n", data);
	
	BIO_free_all(mem);
}

static SSL_CTX* prepare_ssl_ctx()
{
	SSL_CTX* ctx = NULL;
	X509 *cert = NULL;
	X509 *ca_cert = NULL;
	RSA* rsa = NULL;
	BIO* ca_cert_bio = NULL;
	BIO* cert_bio = NULL;
	BIO* key_bio = NULL;
	
	bool init_done = false;
	int ret = 0;
	
	if (ledger_keys_manager.keys_ready() == false)
	{
		PRINT(ERROR, IAS, "ledger keys are not initialized\n\n");
		return NULL;
	}
	
	do 
	{
		const SSL_METHOD* method = TLS_client_method();
		if (method == NULL)
		{
			PRINT(ERROR, IAS, "TLS_client_method failed\n");
			break;
		}
		
		// use the method to initialize a context
		ctx = SSL_CTX_new(method);
		if (ctx == NULL)
		{
			PRINT(ERROR, IAS, "SSL_CTX_new failed\n");
			break;
		}
		
		// create a new memory buffer to hold the client certificate data
		cert_bio = BIO_new_mem_buf((void*)&ledger_keys_manager.get_ledger_base_keys()->ias_certificate_str, -1); // -1 means lenght will be determined by str_len and buffer is read-only
		if (cert_bio == NULL)
		{
			PRINT(ERROR, IAS, "BIO_new_mem_buf failed\n");
			break;
		}
		
		// translate the memory buffer to certificate object
		cert = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);
		if (cert == NULL)
		{
			PRINT(ERROR, IAS, "PEM_read_bio_X509 failed\n");
			break;
		}
		
		// add the certificate to the context
		ret = SSL_CTX_use_certificate(ctx, cert);
		if (ret != 1)
		{
			PRINT(ERROR, IAS, "SSL_CTX_use_certificate failed with %d\n", ret);
			break;
		}
		
		// create a new memory buffer to hold the key data
		key_bio = BIO_new_mem_buf((void*)&ledger_keys_manager.get_ledger_base_keys()->ias_key_str, -1); // -1 means lenght will be determined by str_len and buffer is read-only
		if (key_bio == NULL)
		{
			PRINT(ERROR, IAS, "BIO_new_mem_buf failed\n");
			break;
		}
		
		// translate the memory buffer to RSA key object
		rsa = PEM_read_bio_RSAPrivateKey(key_bio, NULL, 0, NULL);
		if (rsa == NULL)
		{
			PRINT(ERROR, IAS, "PEM_read_bio_RSAPrivateKey failed\n");
			break;
		}
		
		// add the RSA key to the context
		ret = SSL_CTX_use_RSAPrivateKey(ctx, rsa);
		if (ret != 1)
		{
			PRINT(ERROR, IAS, "SSL_CTX_use_RSAPrivateKey failed with %d\n", ret);
			break;
		}

		// check that the key is OK
		if (SSL_CTX_check_private_key(ctx) != 1)
		{
			PRINT(ERROR, IAS, "SSL_CTX_check_private_key failed\n");
			break;
		}
		
		// create a new memory buffer to hold the root CA data
		ca_cert_bio = BIO_new_mem_buf((void*)ias_ca_cert_buffer, -1); // -1 means lenght will be determined by str_len and buffer is read-only
		if (ca_cert_bio == NULL)
		{
			PRINT(ERROR, IAS, "BIO_new_mem_buf failed\n");
			break;
		}
		
		// translate the memory buffer to certificate object
		ca_cert = PEM_read_bio_X509(ca_cert_bio, NULL, 0, NULL);
		if (ca_cert == NULL)
		{
			PRINT(ERROR, IAS, "PEM_read_bio_X509 failed\n");
			break;
		}
		
		//print_certificate_details(ca_cert);
		
		// get the context certificate store
		X509_STORE* store = SSL_CTX_get_cert_store(ctx);
		if (store == NULL)
		{
			PRINT(ERROR, IAS, "SSL_CTX_get_cert_store failed\n");
			break;
		}
		
		// IMPORTANT - this api is undocumented!! the only documented way of adding CA certificate is directly from a file...
		ret = X509_STORE_add_cert(store, ca_cert);
		if (ret != 1)
		{
			PRINT(ERROR, IAS, "X509_STORE_add_cert failed with %d\n", ret);
			break;
		}
		
		// set verification flags for the context
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); // custom_verify_peer); // enable for debugging of the certificate chain
		SSL_CTX_set_verify_depth(ctx, 4);
		
		init_done = true;
		
	} while (0);
	
	// cleanup
	if (cert != NULL)
		X509_free(cert);
	if (ca_cert != NULL)
		X509_free(ca_cert);
	if (rsa != NULL)
		RSA_free(rsa);
	if (ca_cert_bio != NULL)
		BIO_free(ca_cert_bio);
	if (cert_bio != NULL)
		BIO_free(cert_bio);
	if (key_bio != NULL)
		BIO_free(key_bio);
	
	if (init_done == false && ctx != NULL)
	{
		SSL_CTX_free(ctx);
		ctx = NULL;
	}
		
	return ctx;
}


// create a tls connection, through proxy if one is configured
static bool connect_to_ias(ias_session_t* p_ias_session)
{
	bool retval = false;
	int res = 1;

	SSL_CTX* ctx = NULL;
	SSL *ssl = NULL;
	X509 *cert = NULL;
	
	X509_VERIFY_PARAM *param = NULL;

	do {
		
		ctx = prepare_ssl_ctx();
		if (ctx == NULL)
		{
			PRINT(ERROR, IAS, "prepare_ssl_ctx failed\n");
			break;
		}
		
		ssl = SSL_new(ctx);
		if (ssl == NULL)
		{
			PRINT(ERROR, IAS, "SSL_new failed\n");
			break;
		}
		
		SSL_set_fd(ssl, p_ias_session->socket);
		
		// this will make sure that the server certificate indeed matches the required URL (and is not just some legal certificate signed by the root CA)
		param = SSL_get0_param(ssl);
		if (param == NULL)
		{
			PRINT(ERROR, IAS, "SSL_get0_param failed\n");
			break;
		}
		X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
		X509_VERIFY_PARAM_set1_host(param, IAS_HOST_ADDRESS, 0);

		res = SSL_connect(ssl);
		if (res != 1)
		{
			PRINT(ERROR, IAS, "SSL_connect failed, ret %d, error %d, errno %d\n", res, SSL_get_error(ssl, res), errno);
			break;
		}
		
		PRINT(INFO, IAS, "SSL_connect ok\n");
		
		cert = SSL_get_peer_certificate(ssl);
		if (cert == NULL)
		{
			PRINT(ERROR, IAS, "SSL_get_peer_certificate failed\n");
			break;
		}
		
		print_certificate_details(cert);
		
		PRINT(INFO, IAS, "protocol used: %s\n", SSL_get_cipher_version(ssl));
		PRINT(INFO, IAS, "encryption cipher: %s\n", SSL_get_cipher(ssl));
		
		retval = true;
	
	} while(0);
		
	if (cert != NULL)
		X509_free(cert);
		
	if (retval == false)
	{
		if (ssl != NULL)
		{
			SSL_shutdown(ssl);
			SSL_free(ssl);	
		}
		if (ctx != NULL)
		{
			SSL_CTX_free(ctx);
		}	
	}
	else // success, save the ssl and context
	{
		p_ias_session->ssl = ssl;
		p_ias_session->ctx = ctx;
	}
		
	return retval;
}


static bool exchange_data_with_ias(ias_session_t* p_ias_session, char* input, size_t input_len, char* output, size_t* output_len)
{
	bool retval = false;
	int res = 1;
	
	if (p_ias_session == NULL || input == NULL || input_len == 0 || output == NULL || *output_len == 0)
	{
		PRINT(ERROR, IAS, "bad input parameters\n");
		return false;
	}
	
	if (input_len > ONE_GB || *output_len > ONE_GB)
	{
		PRINT(ERROR, IAS, "input length or output length are too big\n");
		return false;
	}
	
	do {
		res = SSL_write(p_ias_session->ssl, input, (int)input_len);
		if (res <= 0)
		{
			PRINT(ERROR, IAS, "SSL_write failed, ret %d, error %d\n", res, SSL_get_error(p_ias_session->ssl, res));
			break;
		}
		if ((size_t)res != input_len)
		{
			PRINT(ERROR, IAS, "SSL_write was partial, only %d of %ld bytes, ssl error %d\n", res, input_len, SSL_get_error(p_ias_session->ssl, res));
			break;
		}
		PRINT(INFO, IAS, "SSL_write (%d bytes):\n%s\n\n", res, input);

		
		res = SSL_read(p_ias_session->ssl, output, (int)*output_len - 1);
		if (res <= 0)
		{
			PRINT(ERROR, IAS, "SSL_read failed, ret %d, error %d\n", res, SSL_get_error(p_ias_session->ssl, res));
			break;
		}
		output[res] = '\0';
		//PRINT(INFO, IAS, "SSL_read (%d bytes):\n%s\n", res, output);
		
		*output_len = res; // set actual bytes read
		
		retval = true;
		
	} while (0);
	
	return retval;
}


// this function was modified from the original IAS test code
// NOTE - this function modifies the input buffer!
#define MAX_STRINGS 30
static bool parse_ias_response(char* buffer, size_t buf_len, int* code, char** content, char** report_sig, char** certificate)
{
	bool new_str = true;
	char* strings[MAX_STRINGS] = {};
	size_t strings_index = 0;
	size_t actual_content_len = 0;
	size_t expected_content_len = 0;
	size_t i = 0;

	bool code_found = false;
	bool id_found = false;
	bool date_found = false;
	bool connection_found = false;
	bool type_found = false;
	bool length_found = false;
	bool report_sig_found = false;
	bool certificate_found = false;
	
	// these 2 are used 4 times so use a variable for them, the others are only used once or twice
	size_t report_sig_header_len = strnlen("X-IASReport-Signature: ", MAXLEN_FIXED_STRING);
	size_t certificate_header_len = strnlen("x-iasreport-signing-certificate: ", MAXLEN_FIXED_STRING);
	
	PRINT(INFO, IAS, "\nParse IAS response:\n");
	
	if (buffer == NULL || buf_len == 0)
	{
		PRINT(ERROR, IAS, "bad input parameters\n");
		return false;
	}
	
	if (buf_len > ONE_GB)
	{
		PRINT(ERROR, IAS, "buffer length is too big\n");
		return false;
	}

	// split the response with the separator being \r\n
	for (i = 0 ; i < buf_len-1 ; i++)
	{
		if (strings_index >= MAX_STRINGS)
		{
			PRINT(ERROR, IAS, "buffer have too many sections\n");
			return false;
		}
		
		if (new_str == true)
		{
			strings[strings_index++] = &buffer[i];
			new_str = false;
		}

		if (buffer[i] == '\r')
		{
			if (buffer[i+1] != '\n')
				return false; // error in the response buffer
			buffer[i++] = '\0';
			buffer[i] = '\0';
			new_str = true;
		}
	}
	
	// parse the different header fields
	for (i = 0 ; i < strings_index ; i++)
	{
		if (code_found == false && strncasecmp("HTTP/1.1", strings[i], strnlen("HTTP/1.1", MAXLEN_FIXED_STRING)) == 0)
		{
			if (sgxssl_sscanf(strings[i], "HTTP/1.1 %d", code) != 1)
			{
				PRINT(ERROR, IAS, "parsing response failed, bad code\n");
				break;
			}
			code_found = true;
			
			PRINT(INFO, IAS, "\tresponse code: %d\n", *code);
			
			continue;
		}
		
		// HTTP regular headers

		if (type_found == false && strncasecmp("content-type: ", strings[i], strnlen("content-type: ", MAXLEN_FIXED_STRING)) == 0)
		{			
			type_found = true;
			
			PRINT(INFO, IAS, "\tresponse type: %s\n", &strings[i][strnlen("content-type: ", MAXLEN_FIXED_STRING)]);

			continue;
		}

		if (length_found == false && strncasecmp("content-length: ", strings[i], strnlen("content-length: ", MAXLEN_FIXED_STRING)) == 0)
		{
			if (sgxssl_sscanf(strings[i], "content-length: %d", &expected_content_len) != 1)
			{
				PRINT(ERROR, IAS, "parsing response failed, bad content length\n");
				break;
			}
			
			length_found = true;
			
			PRINT(INFO, IAS, "\tcontent length: %s\n", &strings[i][strnlen("content-length: ", MAXLEN_FIXED_STRING)]);
			
			continue;
		}

		if (date_found == false && strncasecmp("date: ", strings[i], strnlen("date: ", MAXLEN_FIXED_STRING)) == 0)
		{
			date_found = true;
			
			PRINT(INFO, IAS, "\tresponse date: %s\n", &strings[i][strnlen("date: ", MAXLEN_FIXED_STRING)]);
			
			continue;
		}

		if (connection_found == false && strncasecmp("connection: ", strings[i], strnlen("connection: ", MAXLEN_FIXED_STRING)) == 0)
		{
			connection_found = true;
			
			PRINT(INFO, IAS, "\tresponse connection: %s\n", &strings[i][strnlen("connection: ", MAXLEN_FIXED_STRING)]);
			
			continue;
		}
		
		if (strncasecmp("warning: ", strings[i], strnlen("warning: ", MAXLEN_FIXED_STRING)) == 0)
		{			
			PRINT(INFO, IAS, "\t%s\n", strings[i]);

			continue;
		}

		// IAS dedicated headers
		
		if (id_found == false && strncasecmp("request-id: ", strings[i], strnlen("request-id: ", MAXLEN_FIXED_STRING)) == 0)
		{			
			id_found = true;
			
			PRINT(INFO, IAS, "\trequest id: %s\n", &strings[i][strnlen("request-id: ", MAXLEN_FIXED_STRING)]);

			continue;
		}
		
		if (report_sig_found == false && strncasecmp("X-IASReport-Signature: ", strings[i], report_sig_header_len) == 0)
		{
			if (report_sig == NULL)
			{
				PRINT(ERROR, IAS, "report_sig pointer is NULL\n");
				break;
			}

			size_t report_sig_len = strnlen(strings[i], MAXLEN_SIGNATURE_STRING) - report_sig_header_len + 1;
			if (report_sig_len >= MAXLEN_SIGNATURE_STRING - report_sig_header_len + 1 || report_sig_len < MINLEN_SIGNATURE_STRING)
			{
				PRINT(ERROR, IAS, "report_sig is too long or too short (%ld bytes)\n", report_sig_len);
				break;
			}
			
			char* tmp_report_sig = (char*)malloc(report_sig_len);
			if (tmp_report_sig == NULL)
			{
				PRINT(ERROR, IAS, "malloc failed\n");
				break;
			}
			if (safe_strncpy(tmp_report_sig, report_sig_len, &(strings[i][report_sig_header_len]), report_sig_len) == false)
			{
				free(tmp_report_sig);
				PRINT(ERROR, CRYPTO, "safe_strncpy failed\n");
				break;
			}
			
			*report_sig = tmp_report_sig;
			report_sig_found = true;
			
			PRINT(INFO, IAS, "\treport signature: %s\n", *report_sig);
			
			continue;
		}
		
		if (certificate_found == false && strncasecmp("x-iasreport-signing-certificate: ", strings[i], certificate_header_len) == 0)
		{
			if (certificate == NULL)
			{
				PRINT(ERROR, IAS, "certificate pointer is NULL\n");
				break;
			}

			size_t certificate_len = strnlen(strings[i], MAXLEN_CERTIFICATE_STRING) - certificate_header_len + 1;
			if (certificate_len >= MAXLEN_CERTIFICATE_STRING - certificate_header_len + 1 || certificate_len < MINLEN_CERTIFICATE_STRING)
			{
				PRINT(ERROR, IAS, "certificate is too long or too short (%ld bytes)\n", certificate_len);
				break;
			}
			
			char* tmp_certificate = (char*)malloc(certificate_len);
			if (tmp_certificate == NULL)
			{
				PRINT(ERROR, IAS, "malloc failed\n");
				break;
			}
			if (safe_strncpy(tmp_certificate, certificate_len, &(strings[i][certificate_header_len]), certificate_len) == false)
			{
				free(tmp_certificate);
				PRINT(ERROR, CRYPTO, "safe_strncpy failed\n");
				break;
			}
			
			*certificate = tmp_certificate;
			certificate_found = true;
			
			PRINT(INFO, IAS, "\tsigning certificate: %s\n", *certificate);
			
			continue;
		}
		
		if (strncasecmp("Advisory-URL: ", strings[i], strnlen("Advisory-URL: ", MAXLEN_FIXED_STRING)) == 0)
		{			
			PRINT(INFO, IAS, "\t%s\n", strings[i]);

			continue;
		}
		
		if (strncasecmp("Advisory-IDs: ", strings[i], strnlen("Advisory-IDs: ", MAXLEN_FIXED_STRING)) == 0)
		{			
			PRINT(INFO, IAS, "\t%s\n", strings[i]);

			continue;
		}
		
		// empty header
				
		if (strnlen(strings[i], MAXLEN_FIXED_STRING) == 0)
		{
			// \r\n\r\n
			continue;
		}

		// none of the above - some unrecognized header (there are many in the HTTP standard)
		if (i != strings_index - 1)
		{
			PRINT(INFO, IAS, "unrecognized header or duplicated header\n%s\n", strings[i]);
			continue;
		}
		
		if (expected_content_len == 0)
		{
			// it is the last one, but since we don't expect content, it must be just another unrecognized header
			PRINT(INFO, IAS, "unrecognized header or duplicated header\n%s\n", strings[i]);
			continue;
		}
		
		actual_content_len = strnlen(strings[i], MAXLEN_CONTENT_STRING) + 1;
		if (actual_content_len >= MAXLEN_CONTENT_STRING + 1)
		{
			PRINT(ERROR, IAS, "content is too long\n");
			break;
		}
		
		char* tmp_content = (char*)malloc(actual_content_len);
		if (tmp_content == NULL)
		{
			PRINT(ERROR, IAS, "malloc failed\n");
			break;
		}
		if (safe_strncpy(tmp_content, actual_content_len, strings[i], actual_content_len) == false)
		{
			free(tmp_content);
			PRINT(ERROR, CRYPTO, "safe_strncpy failed\n");
			break;
		}
		
		*content = tmp_content;		
		PRINT(INFO, IAS, "\tresponse content (%ld bytes): %s\n", actual_content_len, *content);
	}
	
	if (i != strings_index || // parsing error
		actual_content_len < expected_content_len) // actual content is usually one to two bytes longer
	{
		PRINT(ERROR, IAS, "parsing failed, either check previous error -or- content is shorter than expected (%ld < %ld)\n", actual_content_len, expected_content_len);
		
		if (content != NULL && *content != NULL)
		{
			free(*content);
			*content = NULL;
		}
		
		if (report_sig != NULL && *report_sig != NULL)
		{
			free(*report_sig);
			*report_sig = NULL;
		}
		
		if (certificate != NULL && *certificate != NULL)
		{
			free(*certificate);
			*certificate = NULL;
		}
		return false;
	}

	return true;
}


static bool get_ias_quote_status(cJSON* cj_quote_status, ias_quote_status_t* status)
{
	bool retval = false;
	
	for (uint32_t i = 0 ; i < QUOTE_STRINGS_COUNT ; i++)
	{
		if (strncasecmp(cj_quote_status->valuestring, quote_status_strings[i], strnlen(quote_status_strings[i], MAXLEN_FIXED_STRING)) == 0)
		{
			*status = (ias_quote_status_t)i;
			retval = true;
			break;
		}
	}
	
	return retval;
}

#ifdef VERIFY_PSE_ATTESTATION
static bool get_ias_pse_status(cJSON* cj_pse_status, ias_pse_status_t* status)
{
	bool retval = false;
	
	for (uint32_t i = 0 ; i < PSE_STRINGS_COUNT ; i++)
	{
		if (strncasecmp(cj_pse_status->valuestring, pse_status_strings[i], strnlen(pse_status_strings[i], MAXLEN_FIXED_STRING)) == 0)
		{
			*status = (ias_pse_status_t)i;
			retval = true;
			break;
		}
	}
	
	return retval;
}
#endif

// https://www.w3schools.com/tags/ref_urlencode.asp
static bool convert_http_encoding_to_normal(const char* input, char* output)
{
	size_t i = 0;
	size_t j = 0;
	
	size_t input_len = strnlen(input, MAXLEN_CERTIFICATE_STRING); // todo - add size check
	
	for ( ; i < input_len ; i++)
	{
		if (input[i] == '%') // only trying to convert the base64 encodings which are also special http letters (+ and /) and the ones used in certificate string (space and new line)
		{
			if (input[i+1] == '2' && input[i+2] == '0')
				output[j] = ' ';
			else if (input[i+1] == '2' && input[i+2] == 'B')
				output[j] = '+';
			else if (input[i+1] == '2' && input[i+2] == 'F')
				output[j] = '/';
			else if (input[i+1] == '3' && input[i+2] == 'D')
				output[j] = '=';
			else if (input[i+1] == '0' && input[i+2] == 'A')
				output[j] = '\n';
			else
			{
				PRINT(ERROR, IAS, "unknown special char %c%c%c\n", input[i], input[i+1], input[i+2]);
				break;
			}
				
			i+=2;
		}
		else // copy as-is
		{
			output[j] = input[i];
		}
		j++;
	}
	output[j] = '\0'; // terminate the result string
	
	if (i != strnlen(input, MAXLEN_CERTIFICATE_STRING))
	{
		return false;
	}
	
	return true;
}


static bool verify_ias_signature(char* report, char* report_sig_cert, char* report_sig)
{
	bool retval = false;
	
	char* fixed_cert = NULL;
	
	BIO* ca_cert_bio = NULL;
	X509* ca_cert = NULL;
	
	BIO* cert_bio = NULL;
	X509* cert = NULL;
	
	X509_STORE* store = NULL;
	X509_STORE_CTX* store_ctx = NULL;
		
	EVP_PKEY* evp_pkey = NULL;
	RSA* rsa = NULL;
	
	sha256_data_t report_sha256 = {0};
	
	uint8_t* report_sig_blob = NULL;
	
	do {
		// load the static root CA into X509_STORE
		
		ca_cert_bio = BIO_new_mem_buf((void*)attestation_ca_cert_buffer, -1); // -1 means length will be determined by str_len and buffer is read-only
		if (ca_cert_bio == NULL)
		{
			PRINT(ERROR, IAS, "BIO_new_mem_buf failed\n");
			break;
		}
		
		ca_cert = PEM_read_bio_X509(ca_cert_bio, NULL, 0, NULL);
		if (ca_cert == NULL)
		{
			PRINT(ERROR, IAS, "PEM_read_bio_X509 failed\n");
			break;
		}
		
		//print_certificate_details(ca_cert);
				
		store = X509_STORE_new();
		if (store == NULL)
		{
			PRINT(ERROR, IAS, "X509_STORE_new failed\n");
			break;
		}
		
		// IMPORTANT - this api is undocumented!! the only documented way of adding CA certificate is directly from a file...
		int ret = X509_STORE_add_cert(store, ca_cert);
		if (ret != 1)
		{
			PRINT(ERROR, IAS, "X509_STORE_add_cert failed with %d\n", ret);
			break;
		}
		
		store_ctx = X509_STORE_CTX_new();
		if (store_ctx == NULL)
		{
			PRINT(ERROR, IAS, "X509_STORE_CTX_new failed\n");
			break;
		}
			
		// the certificate chain from the IAS server comes with some special characters converted to HTTP encoding
		// need to convert them back to normal encoding
		fixed_cert = (char*)malloc(strnlen(report_sig_cert, MAXLEN_CERTIFICATE_STRING)+1); // todo - add size check
		if (fixed_cert == NULL)
		{
			PRINT(ERROR, IAS, "malloc failed\n");
			break;
		}
		
		if (convert_http_encoding_to_normal(report_sig_cert, fixed_cert) == false)
		{
			PRINT(ERROR, IAS, "failed to convert certificate's http encoding\n");
			break;
		}
		
		//PRINT(INFO, IAS, "fixed certificate chain:\n %s\n", fixed_cert);
		
		// the buffer contains 2 certificates, the report signing certificate and the root certificate,
		// the root certificate should be identical to the static hard coded certificate, verify it's indeed the case
		// locate the start point of that second certificate
		char* root_ca_start = strstr(&fixed_cert[10], "-----BEGIN CERTIFICATE-----"); // todo - the '10' is to skip the first certificate
		if (root_ca_start == NULL)
		{
			PRINT(ERROR, IAS, "certificate chain do not hold 2 certificates\n");
			break;
		}
		if (strcmp(attestation_ca_cert_buffer, root_ca_start) != 0)
		{
			PRINT(ERROR, IAS, "Root CA in the report is not the one expected\n");
			break;
		}
		
		// load the signing certificate
		cert_bio = BIO_new_mem_buf((void*)fixed_cert, -1); // -1 means length will be determined by str_len and buffer is read-only
		if (cert_bio == NULL)
		{
			PRINT(ERROR, IAS, "BIO_new_mem_buf failed\n");
			break;
		}
		
		cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL); // read the first certificate
		
		print_certificate_details(cert);
		
		// initialize context with the store that holds the CA certificate, and the signing certificate	
		X509_STORE_CTX_init(store_ctx, store, cert, NULL);
		
		// this checks the certificate is signed properly by the root CA
		// todo - verify if there are any flags i need to set before this check
		ret = X509_verify_cert(store_ctx);
		if (ret != 1)
		{
			PRINT(ERROR, IAS, "X509_verify_cert returned %d\n", ret);
			break;
		}
		
		// after we established that the certificate is properly signed, need to verify the signature
		// we need 3 things:
		// 1. hash of the report
		// 2. the signature itself
		// 3. the public part of the signing key
		
		// calculate the SHA256 hash of the report
		if (sha256_msg((const uint8_t*)report, (uint32_t)strnlen(report, MAXLEN_CONTENT_STRING), &report_sha256) == false)
		{
			PRINT(ERROR, IAS, "sha256_msg failed\n");
			break;
		}
		
		// decode the signature itself
		report_sig_blob = (uint8_t*)malloc(strnlen(report_sig, MAXLEN_SIGNATURE_STRING)); // todo - move to parameter and add size check
		int report_sig_len = EVP_DecodeBlock(report_sig_blob, (const uint8_t*)report_sig, (uint32_t)strnlen(report_sig, MAXLEN_SIGNATURE_STRING));
		if (report_sig_len < 0)
		{
			PRINT(ERROR, MAIN, "EVP_DecodeBlock failed, returned %d\n", report_sig_len);
			break;
		}

		// get the rsa public key from the already-verified certificate
		evp_pkey = X509_get_pubkey(cert);
		if (evp_pkey == NULL)
		{
			PRINT(ERROR, IAS, "X509_get_pubkey failed\n");
			break;
		}
		rsa = EVP_PKEY_get1_RSA(evp_pkey);
		if (rsa == NULL)
		{
			PRINT(ERROR, IAS, "EVP_PKEY_get1_RSA failed\n");
			break;
		}
		
		// now verify the signature is valid		
		ret = RSA_verify(NID_sha256, report_sha256, SHA256_DIGEST_LENGTH, report_sig_blob, 256, rsa); // todo - report_sig_len == 258...check this issue
		if (ret != 1)
		{
			PRINT_CRYPTO_ERROR("RSA_verify");
			break;
		}
		
		retval = true;
	} while(0);
	
	// cleanup
	if (fixed_cert != NULL)
		free(fixed_cert);
	
	if (rsa != NULL)
		RSA_free(rsa);
	if (evp_pkey != NULL)
		EVP_PKEY_free(evp_pkey);
	
	if (store != NULL)
		X509_STORE_free(store);
	if (store_ctx != NULL)
		X509_STORE_CTX_free(store_ctx);
		
	if (cert_bio != NULL)
		BIO_free(cert_bio);
	if (cert != NULL)
		X509_free(cert);
	if (ca_cert_bio != NULL)
		BIO_free(ca_cert_bio);
	if (ca_cert != NULL)
		X509_free(ca_cert);
		
	if (report_sig_blob != NULL)
		free(report_sig_blob);
	
	return retval;
}


static bool parse_ias_report(const char* report, const unsigned char* nonce_str, const sgx_quote_t* p_quote, const sgx_ps_sec_prop_desc_t* p_ps_sec_prop, ias_att_report_t* p_ias_report)
{
	bool retval = false;
	
	cJSON* cj_report = NULL;
	
	ias_platform_info_t* p_ias_platform_info = NULL;
	
	unsigned char* b64_quote_str = NULL;
	
	sha256_data_t ps_sec_prop_sha256 = {0};
	unsigned char* ias_sha256 = NULL;
	
	long length = 0;
	size_t str_len = 0;
	
	if (report == NULL || nonce_str == NULL || p_quote == NULL || p_ps_sec_prop == NULL || p_ias_report == NULL)
	{
		PRINT(ERROR, IAS, "wrong input parameters\n");
		return false;
	}
	
	do {
		cj_report = cJSON_Parse(report);
		if (cj_report == NULL)
		{
			PRINT(ERROR, IAS, "cJSON_Parse on content failed\n");
			break;
		}
		
		cJSON* cj_object = cJSON_GetObjectItem(cj_report, "nonce");
		if (cj_object == NULL)
		{
			PRINT(ERROR, IAS, "cJSON_GetObjectItem failed to retrieve nonce\n");
			break;
		}
		if (strncmp(cj_object->valuestring, (const char*)nonce_str, IAS_NONCE_SIZE*2) != 0)
		{
			PRINT(ERROR, IAS, "nonce in reply is not the same as the one from the request\n");
			break;
		}
		
		cj_object = cJSON_GetObjectItem(cj_report, "isvEnclaveQuoteStatus");
		if (cj_object == NULL)
		{
			PRINT(ERROR, IAS, "cJSON_GetObjectItem failed to retrieve isvEnclaveQuoteStatus\n");
			break;
		}
		if (get_ias_quote_status(cj_object, &p_ias_report->status) == false)
		{
			PRINT(ERROR, IAS, "get_ias_quote_status failed\n");
			break;
		}
		
		cj_object = cJSON_GetObjectItem(cj_report, "revocationReason");
		if (cj_object != NULL)
		{
			if (p_ias_report->status != IAS_QUOTE_GROUP_REVOKED)
			{
				PRINT(ERROR, IAS, "revocationReason is present even when it is should not!\n");
				break;
			}
			p_ias_report->revocation_reason = cj_object->valueint;
		}
		
#ifdef VERIFY_PSE_ATTESTATION
		cj_object = cJSON_GetObjectItem(cj_report, "pseManifestStatus");
		if (cj_object == NULL)
		{
			PRINT(ERROR, IAS, "cJSON_GetObjectItem failed to retrieve pseManifestStatus\n");
			break;
		}
		if (get_ias_pse_status(cj_object, &p_ias_report->pse_status) == false)
		{
			PRINT(ERROR, IAS, "get_ias_pse_status failed\n");
			break;
		}
#else
		(void)ps_sec_prop_sha256;
#endif
		
		cj_object = cJSON_GetObjectItem(cj_report, "platformInfoBlob");
		if (cj_object != NULL)
		{		
			if (p_ias_report->status == IAS_QUOTE_OK)
			{
#ifdef VERIFY_PSE_ATTESTATION
			if (p_ias_report->pse_status == IAS_PSE_OK)
#endif
				{
					PRINT(ERROR, IAS, "platformInfoBlob is present even when it is should not!\n");
					break;
				}
			}
			
			p_ias_platform_info = (ias_platform_info_t*)OPENSSL_hexstr2buf(cj_object->valuestring, &length);
			if (p_ias_platform_info == NULL)
			{
				PRINT(ERROR, IAS, "OPENSSL_hexstr2buf failed\n");
				break;
			}
			if (length != sizeof(ias_platform_info_t))
			{
				PRINT(ERROR, IAS, "size of platform info is different than expected: %ld != %ld\n", length, sizeof(ias_platform_info_t));
				break;
			}
			
			uint16_t size = (uint16_t)(((uint16_t)p_ias_platform_info->size_1 * 256) + p_ias_platform_info->size_2); // convert BE to LE
			
			if (p_ias_platform_info->type != IAS_PIB_TYPE || p_ias_platform_info->version != IAS_PIB_VERSION || size != sizeof(sgx_platform_info_t))
			{
				PRINT(ERROR, IAS, "PIB error, type: %hhd (expected %d), version: %hhd (expected %d), size: %hd (expected %ld)\n", 
						p_ias_platform_info->type, IAS_PIB_TYPE, p_ias_platform_info->version, IAS_PIB_VERSION, size, sizeof(sgx_platform_info_t));
				break;
			}
			
			if (safe_memcpy(&p_ias_report->platform_info, sizeof(sgx_platform_info_t), &p_ias_platform_info->platform_info, sizeof(sgx_platform_info_t)) == false)
			{
				PRINT(ERROR, IAS, "safe_memcpy failed\n");
				break;
			}
			p_ias_report->platform_info_valid = 1;
		}
		
#ifdef VERIFY_PSE_ATTESTATION
		// verify the PSE manifest hash in the attestation report is the one we sent
		cj_object = cJSON_GetObjectItem(cj_report, "pseManifestHash");
		if (cj_object == NULL)
		{
			PRINT(ERROR, IAS, "cJSON_GetObjectItem failed to retrieve pseManifestHash\n");
			break;
		}
		
		ias_sha256 = OPENSSL_hexstr2buf(cj_object->valuestring, &length);
		if (ias_sha256 == NULL)
		{
			PRINT(ERROR, IAS, "OPENSSL_hexstr2buf failed\n");
			break;
		}
		if (length != SHA256_DIGEST_LENGTH)
		{
			PRINT(ERROR, IAS, "PSE manifest sha256 size is incorrect\n");
			break;
		}

		if (sha256_msg((const uint8_t*)p_ps_sec_prop, sizeof(sgx_ps_sec_prop_desc_t), &ps_sec_prop_sha256) == false)
		{
			PRINT(ERROR, IAS, "sha256_msg failed\n");
			break;
		}
		
		// todo - memcmp
		int i = 0;
		for ( ; i < SHA256_DIGEST_LENGTH ; i++)
		{
			if (ias_sha256[i] != ps_sec_prop_sha256[i])
				break;
		}
		if (i != SHA256_DIGEST_LENGTH)
		{
			PRINT(ERROR, IAS, "PSE manifest sha256 mismatch\n");
			break;
		}
#endif
		
		// verify the enclave quote in the attestation report is the one we sent
		cj_object = cJSON_GetObjectItem(cj_report, "isvEnclaveQuoteBody");
		if (cj_object == NULL)
		{
			PRINT(ERROR, IAS, "cJSON_GetObjectItem failed to retrieve isvEnclaveQuoteBody\n");
			break;
		}
		
		// convert again the quote to base64 string, but only part of it this time
		uint32_t base_quote_size = sizeof(sgx_quote_t) - sizeof(uint32_t); // quote without the sig_len (and the signature itself which is not a part of the structure)
		
		b64_quote_str = (unsigned char*)malloc(base_quote_size*2 + 1);
		if (b64_quote_str == NULL)
		{
			PRINT(ERROR, IAS, "malloc failed\n");
			break;
		}
		
		str_len = EVP_EncodeBlock(b64_quote_str, (const uint8_t*)p_quote, base_quote_size);
		if (str_len == 0 || str_len > base_quote_size*2)
		{
			PRINT(ERROR, IAS, "EVP_EncodeBlock failed\n");
			break;
		}
		
		if (strncmp((const char*)b64_quote_str, cj_object->valuestring, str_len) != 0)
		{
			PRINT(ERROR, IAS, "isvEnclaveQuoteBody different from the one we sent\n");
			break;
		}
		
		// we do not try to parse "epidPseudonym" since we don't use linkable attestation
		
		// todo - currently not doing anything with the id and the time
		
		retval = true;
		
	} while(0);
	
	// cleanup
	if (cj_report != NULL)
		cJSON_Delete(cj_report);
	if (p_ias_platform_info != NULL)
		OPENSSL_free(p_ias_platform_info);
	if (ias_sha256 != NULL)
		OPENSSL_free(ias_sha256);
	if (b64_quote_str != NULL)
		free(b64_quote_str);
	
	return retval;
}


static bool prepare_ias_report_request(const unsigned char* nonce_str, const sgx_quote_t* p_quote, size_t quote_size, const sgx_ps_sec_prop_desc_t* p_ps_sec_prop, char** input_buffer)
{
	bool retval = false;
	
	size_t str_len = 0;
	unsigned char* b64_quote_str = NULL;
	unsigned char* b64_ps_str = NULL;
	char* json_enclave_str = NULL;
	
	cJSON* cj_main = NULL;

// todo - add quote_size check
	
	do {
		
		// prepare enclave quote
		b64_quote_str = (unsigned char*)malloc(quote_size*2 + 1);
		if (b64_quote_str == NULL)
		{
			PRINT(ERROR, IAS, "malloc failed\n");
			break;
		}
		
		// convert to base64 string
		str_len = EVP_EncodeBlock(b64_quote_str, (const uint8_t*)p_quote, (int32_t)quote_size);
		if (str_len == 0 || str_len > quote_size*2)
		{
			PRINT(ERROR, IAS, "EVP_EncodeBlock failed\n");
			break;
		}
		
#ifdef VERIFY_PSE_ATTESTATION
		// prepare pse manifest
		// todo - do we need the pse quote?
		b64_ps_str = (unsigned char*)malloc(sizeof(sgx_ps_sec_prop_desc_t)*2 + 1);
		if (b64_ps_str == NULL)
		{
			PRINT(ERROR, IAS, "malloc failed\n");
			break;
		}
		
		// convert to base64 string
		str_len = EVP_EncodeBlock(b64_ps_str, (const uint8_t*)p_ps_sec_prop, sizeof(sgx_ps_sec_prop_desc_t));
		if (str_len == 0 || str_len > sizeof(sgx_ps_sec_prop_desc_t)*2)
		{
			PRINT(ERROR, IAS, "EVP_EncodeBlock failed\n");
			break;
		}
#else
		(void)p_ps_sec_prop;
#endif
		
		cj_main = cJSON_CreateObject();
		if (cj_main == NULL)
		{
			PRINT(ERROR, IAS, "cJSON_CreateObject failed\n");
			break;
		}
		
		if (cJSON_AddStringToObject(cj_main, "isvEnclaveQuote", (char*)b64_quote_str) == NULL)
		{
			PRINT(ERROR, IAS, "cJSON_AddStringToObject failed\n");
			break;
		}
#ifdef VERIFY_PSE_ATTESTATION
		if (cJSON_AddStringToObject(cj_main, "pseManifest", (char*)b64_ps_str) == NULL)
		{
			PRINT(ERROR, IAS, "cJSON_AddStringToObject failed\n");
			break;
		}
#endif
		if (cJSON_AddStringToObject(cj_main, "nonce", (char*)nonce_str) == NULL)
		{
			PRINT(ERROR, IAS, "cJSON_AddStringToObject failed\n");
			break;
		}

		json_enclave_str = cJSON_PrintUnformatted(cj_main);
		if (json_enclave_str == NULL)
		{
			PRINT(ERROR, IAS, "cJSON_PrintUnformatted failed\n");
			break;
		}		
		
		uint32_t json_enclave_str_len = (uint32_t)strnlen(json_enclave_str, MAXLEN_CONTENT_STRING);
		if (json_enclave_str_len < 1500) // some error happened, this should be close to 2000
		{
			PRINT(ERROR, IAS, "cJSON failed\n");
			break;
		}
		
		size_t input_buffer_size = 256 + json_enclave_str_len; // 256 are for the header and the length variable
		
		*input_buffer = (char*)malloc(input_buffer_size);
		if (*input_buffer == NULL)
		{
			PRINT(ERROR, IAS, "malloc failed\n");
			break;
		}
			
		snprintf(*input_buffer, input_buffer_size, REPORT_REQUEST, json_enclave_str_len, json_enclave_str); // todo - check return value
		
		retval = true;
		
	} while(0);
	
	// cleanup
	if (cj_main != NULL)
		cJSON_Delete(cj_main);
	if (b64_quote_str != NULL)
		free(b64_quote_str);
	if (b64_ps_str != NULL)
		free(b64_ps_str);
	if (json_enclave_str != NULL)
		free(json_enclave_str);
	
	return retval;
}

/*
#if !defined(SWAP_ENDIAN_DW)
    #define SWAP_ENDIAN_DW(dw)	((((dw) & 0x000000ff) << 24)                \
    | (((dw) & 0x0000ff00) << 8)                                            \
    | (((dw) & 0x00ff0000) >> 8)                                            \
    | (((dw) & 0xff000000) >> 24))
#endif
#if !defined(SWAP_ENDIAN_32B)
    #define SWAP_ENDIAN_32B(ptr)                                            \
{\
    unsigned int temp = 0;                                                  \
    temp = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[0]);                       \
    ((unsigned int*)(ptr))[0] = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[7]);  \
    ((unsigned int*)(ptr))[7] = temp;                                       \
    temp = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[1]);                       \
    ((unsigned int*)(ptr))[1] = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[6]);  \
    ((unsigned int*)(ptr))[6] = temp;                                       \
    temp = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[2]);                       \
    ((unsigned int*)(ptr))[2] = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[5]);  \
    ((unsigned int*)(ptr))[5] = temp;                                       \
    temp = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[3]);                       \
    ((unsigned int*)(ptr))[3] = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[4]);  \
    ((unsigned int*)(ptr))[4] = temp;                                       \
}
#endif
*/

ias_session_t* ias_create_session(uint32_t ias_socket)
{
	ias_session_t* p_ias_session = (ias_session_t*)malloc(sizeof(ias_session_t));
	if (p_ias_session == NULL)
		return NULL;
		
	p_ias_session->socket = ias_socket;
	p_ias_session->ssl = NULL;
	p_ias_session->ctx = NULL;
	
	if (connect_to_ias(p_ias_session) == false)
	{
		free(p_ias_session);
		p_ias_session = NULL;
	}
	
	return p_ias_session;
}


void ias_destroy_session(ias_session_t* p_ias_session)
{
	if (p_ias_session == NULL)
		return;
		
	if (p_ias_session->ssl != NULL)
	{
		SSL_shutdown(p_ias_session->ssl);
		SSL_free(p_ias_session->ssl);	
	}
	
	if (p_ias_session->ctx != NULL)
	{
		SSL_CTX_free(p_ias_session->ctx);
	}
	
	free(p_ias_session);
	
	PRINT(INFO, IAS, "ias session terminated\n");
}

// todo - need to test this with actual SigRL
bool ias_get_sigrl(ias_session_t* p_ias_session, const sgx_epid_group_id_t gid, size_t* p_sig_rl_size, uint8_t** p_sig_rl)
{
	bool retval = false;
	bool res = false;
	int response_code = 0;
	char* content = NULL;
	char input_buffer[256] = {0};
	char* output_buffer = NULL;
	int32_t sig_rl_actual_size = 0;
	uint8_t* sig_rl = NULL;
	
	if (p_ias_session == NULL || p_sig_rl_size == NULL || p_sig_rl == NULL)
	{
		PRINT(ERROR, IAS, "wrong input parameters\n");
		return false;
	}
	
	do {
	
		uint32_t be_gid = *(uint32_t*)gid;
		
		// todo - understand this, GID is formatted to a string, so i don't think there is LE vs BE
		//be_gid = SWAP_ENDIAN_DW(le_gid);
		//PRINT(INFO, IAS, "gid: %02x%02x%02x%02x, little endian 0x%x, big endian: 0x%x\n", gid[3], gid[2], gid[1], gid[0], le_gid, be_gid);
		
		snprintf(input_buffer, 256, ATTEST_REQUEST, be_gid); // todo - check return value
		size_t input_len = strnlen(input_buffer, 256);
		
		output_buffer = (char*)malloc(IAS_RESPONSE_MAX_LEN);
		if (output_buffer == NULL)
		{
			PRINT(ERROR, IAS, "malloc failed\n");
			break;
		}
		size_t output_len = IAS_RESPONSE_MAX_LEN;
			
		res = exchange_data_with_ias(p_ias_session, input_buffer, input_len, output_buffer, &output_len);
		if (res == false)
		{
			PRINT(ERROR, IAS, "exchange_data_with_ias failed\n");
			break;
		}
		
		// PRINT(INFO, IAS, "\n\n\nIAS response:\n%s\n\n\n", output_buffer);
		
		res = parse_ias_response(output_buffer, output_len, &response_code, &content, NULL, NULL);
		if (res == false)
		{
			PRINT(ERROR, IAS, "parse_ias_response failed\n");
			break;
		}
		
		// expected response should include: HTTP/1.1 200 OK
		if (response_code != 200 && response_code != 201)
		{
			PRINT(ERROR, IAS, "response to attestation check is not ok\n%s\n", output_buffer);
			break;
		}
		
		if (content != NULL) // a SigRL exist, need to convert it from base64
		{
			uint32_t sig_rl_max_len = (uint32_t)strnlen(content, MAXLEN_CONTENT_STRING); // todo - add size check
			
			sig_rl = (uint8_t*)malloc(sig_rl_max_len); // bigger than needed...
			if (sig_rl == NULL)
			{
				PRINT(ERROR, IAS, "malloc failed\n");
				break;
			}
			sig_rl_actual_size = EVP_DecodeBlock(sig_rl, (const unsigned char*)content, sig_rl_max_len);
			if (sig_rl_actual_size < 0)
			{
				PRINT(ERROR, MAIN, "EVP_DecodeBlock failed, returned %d\n", sig_rl_actual_size);
				free(sig_rl);
				sig_rl = NULL;
				sig_rl_actual_size = 0;
				break;
			}	
		}
		
		retval = true;
	
	} while (0);
	
	if (output_buffer != NULL)
		free(output_buffer);
		
	if (content != NULL)
		free(content);
	
	*p_sig_rl = sig_rl;
	*p_sig_rl_size = sig_rl_actual_size;
			
	return retval;
}


bool ias_verify_attestation_evidence(ias_session_t* p_ias_session, const sgx_quote_t* p_quote, size_t quote_size, const sgx_ps_sec_prop_desc_t* p_ps_sec_prop, ias_att_report_t* p_ias_report)
{
	size_t str_len = 0;
	
	unsigned char nonce[IAS_NONCE_SIZE] = {0};
	unsigned char nonce_str[IAS_NONCE_SIZE*2] = {0};
	char* input_buffer = NULL;
	char* output_buffer = NULL;
	
	int response_code = 0;
	char* report = NULL;
	char* report_sig = NULL;
	char* report_sig_cert = NULL;
	
	bool res = false;
	bool retval = false;

// todo - add max quote_size check
	
	if (p_ias_session == NULL || p_quote == NULL || quote_size < sizeof(sgx_quote_t) || p_ps_sec_prop == NULL || p_ias_report == NULL)
	{
		PRINT(ERROR, IAS, "wrong input parameters\n");
		return false;
	}
	
	do {
	
		// prepare nonce - do this here since we also need it for the parsing phase
		res = get_random_bytes(nonce, IAS_NONCE_SIZE);
		if (res == false)
		{
			PRINT(ERROR, IAS, "get_random_bytes failed\n");
			break;
		}
		
		// convert to base64 string
		str_len = EVP_EncodeBlock(nonce_str, nonce, IAS_NONCE_SIZE);
		if (str_len == 0 || str_len > IAS_NONCE_SIZE*2)
		{
			PRINT(ERROR, IAS, "EVP_EncodeBlock failed\n");
			break;
		}
					
		res = prepare_ias_report_request(nonce_str, p_quote, quote_size, p_ps_sec_prop, &input_buffer);
		if (res == false)
		{
			PRINT(ERROR, IAS, "prepare_ias_report_request failed\n");
			break;
		}
		
		size_t input_len = strnlen(input_buffer, MAXLEN_CONTENT_STRING); // todo - add size check
			
		output_buffer = (char*)malloc(IAS_RESPONSE_MAX_LEN); // todo - make sure the size is good
		if (output_buffer == NULL)
		{
			PRINT(ERROR, IAS, "malloc failed\n");
			break;
		}
		size_t output_len = IAS_RESPONSE_MAX_LEN;
			
		res = exchange_data_with_ias(p_ias_session, input_buffer, input_len, output_buffer, &output_len);
		if (res == false)
		{
			PRINT(ERROR, IAS, "exchange_data_with_ias failed\n");
			break;
		}
		
		// PRINT(INFO, IAS, "\n\n\nIAS response:\n%s\n\n\n", output_buffer);
				
		res = parse_ias_response(output_buffer, output_len, &response_code, &report, &report_sig, &report_sig_cert);
		if (res == false)
		{
			PRINT(ERROR, IAS, "parse_ias_response failed\n");
			break;
		}
		
		// expected response should include: HTTP/1.1 200 OK
		if (response_code != 200 && response_code != 201)
		{
			PRINT(ERROR, IAS, "response to attestation check is not ok\n%s\n", output_buffer);
			break;
		}
		
		if (report == NULL || report_sig == NULL || report_sig_cert == NULL)
		{
			PRINT(ERROR, IAS, "response to attestation is missing required parts\n");
			break;
		}
		
		res = verify_ias_signature(report, report_sig_cert, report_sig);
		if (res == false)
		{
			PRINT(ERROR, IAS, "verify_ias_signature failed\n");
			break;
		}
		
		res = parse_ias_report(report, nonce_str, p_quote, p_ps_sec_prop, p_ias_report);
		if (res == false)
		{
			PRINT(ERROR, IAS, "parse_ias_report failed\n");
			break;
		}
		
		retval = true;
		
	} while(0);
	
	// cleanup
	if (input_buffer != NULL)
		free(input_buffer);
	if (output_buffer != NULL)
		free(output_buffer);
		
	if (report != NULL)
		free(report);
	if (report_sig != NULL)
		free(report_sig);
	if (report_sig_cert != NULL)
		free(report_sig_cert);
		
	return retval;
}
