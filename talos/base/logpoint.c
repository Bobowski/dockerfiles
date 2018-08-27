/*
 * Copyright 2017 Imperial College London
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>

#include "openssl/ossl_typ.h"
#include "tls_processing_interface.h"
#include "hashmap.h"
#include "enclaveshim_config.h"

// SGX
#include "sgx_trts.h"
#include "sgx_tcrypto.h"


extern int my_printf(const char *format, ...);

#include <sgx_spinlock.h>
#include "enclaveshim_ocalls.h"

#define THREAD_MUTEX_INITIALIZER SGX_SPINLOCK_INITIALIZER
#define pthread_mutex_lock(m) sgx_spin_lock(m)
#define pthread_mutex_unlock(m) sgx_spin_unlock(m)
typedef sgx_spinlock_t thread_mutex_t;


static const int IV_LENGTH = 12;
static const int TAG_LENGTH = 16;

static unsigned char key[32] = {0};


int encrypt(unsigned char *plaintext, int plaintext_len,
	unsigned char *key, unsigned char *iv,
	unsigned char *ciphertext, unsigned char *tag)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;


	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) return -1;

	/* Initialise the encryption operation. */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		return -1;

	/* Set IV length if default 12 bytes (96 bits) is not appropriate */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LENGTH, NULL))
		return -1;

	/* Initialise key and IV */
	if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) return -1;

	// /* Provide any AAD data. This can be called zero or more times as
	//  * required
	//  */
	// if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
	// 	return -1;

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		return -1;
	ciphertext_len = len;

	/* Finalise the encryption. Normally ciphertext bytes may be written at
	 * this stage, but this does not occur in GCM mode
	 */
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) return -1;
	ciphertext_len += len;

	/* Get the tag */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LENGTH, tag))
		return -1;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len,
	unsigned char *tag, unsigned char *key,
	unsigned char *iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
	int ret;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) return -1;

	/* Initialise the decryption operation. */
	if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		return -1;

	/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LENGTH, NULL))
		return -1;

	/* Initialise key and IV */
	if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) return -1;

	// /* Provide any AAD data. This can be called zero or more times as
	//  * required
	//  */
	// if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
	// 	return -1;

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		return -1;
	plaintext_len = len;

	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LENGTH, tag))
		return -1;

	/* Finalise the decryption. A positive return value indicates success,
	 * anything else is a failure - the plaintext is not trustworthy.
	 */
	ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	if(ret > 0)
	{
		/* Success */
		plaintext_len += len;
		return plaintext_len;
	}
	else
	{
		/* Verify failed */
		return -1;
	}
}




void log_https_request(const SSL* s, char* req, int* len)
{
	if( strncmp( req, "POST", 4 ) != 0 )
	{
		my_printf("%s SSL %p, thisis not POST \n", __func__, s);
		return;
	}

	my_printf( "Before encryption:\n%s", req );


	char* body = strstr( req, "\r\n\r\n" ) + 4;
	int body_len = *len - (body - req);

	char* ciphertext = body;
	char* iv = body + body_len;
	char* tag = body + body_len + IV_LENGTH;

	sgx_read_rand( iv, IV_LENGTH);

	if( !encrypt( body, body_len, key, iv, ciphertext, tag ) )
	{
		my_printf("Failure encryption\n");
		return;
	}

	char* content_length = strstr( req, "Content-Length: ") + strlen("Content-Length: ");

	int str_len = 0;
	while( content_length[str_len] != '\r')
	{
		str_len++;
	}

	s->s3->rrec.length = *len + IV_LENGTH + TAG_LENGTH;
	int written_length = sprintf( content_length, "%d", body_len + IV_LENGTH + TAG_LENGTH );

	int diff = written_length - str_len;

	if( diff == 1 )
	{
		// Move forward
		char* new = body + body_len + IV_LENGTH + TAG_LENGTH;
		char* old = body + body_len + IV_LENGTH + TAG_LENGTH - 1;
		while( old != &content_length[ written_length ] )
		{
			*new = *old;
			new --;
			old --;
		}
		s->s3->rrec.length ++;
	}
	content_length[ written_length ] = '\r';
	content_length[ written_length + 1 ] = '\n';

	my_printf( "After encryption:\n%s", req );

}

void log_https_reply(const SSL* s, char* rep, int* len)
{
	my_printf("%s SSL %p, there is a reply of %d bytes\n", __func__, s, len);

	char* body = strstr( rep, "\r\n\r\n" ) + 4;
	int body_len = *len - (body - rep);

	char* plaintext = body;
	char* iv = body + body_len - IV_LENGTH - TAG_LENGTH;
	char* tag = body + body_len - TAG_LENGTH;

	if( decrypt( body, body_len - IV_LENGTH - TAG_LENGTH, tag, key, iv, plaintext )  > 0 )
	{
		char* content_length = strstr( rep, "Content-Length: ") + strlen("Content-Length: ");
		int str_len = 0;
		while( content_length[str_len] != '\r')
		{
			str_len++;
		}

		*len = *len - IV_LENGTH - TAG_LENGTH;

		int written_length = sprintf( content_length, "%d", body_len - IV_LENGTH - TAG_LENGTH );

		if( written_length - str_len > 0 ) {
			content_length[ written_length ] = ' ';
		}

	}
	else {
		my_printf("FAILURE decrypt\n");
	}
}

void log_set_ssl_type(const void* b, const long type)
{
	(void)b;
	(void)type;
}

void log_new_connection(const SSL* s)
{
	my_printf("%s new connection at %p\n", __func__, s);
}

void log_free_connection(const SSL* s)
{
	my_printf("%s connection at %p has been closed\n", __func__, s);
}

void tls_processing_module_init() {
	tls_processing_register_ssl_read_processing_cb(log_https_request);
	tls_processing_register_ssl_write_processing_cb(log_https_reply);
	tls_processing_register_set_ssl_type_cb(log_set_ssl_type);
	tls_processing_register_new_connection_cb(log_new_connection);
	tls_processing_register_free_connection_cb(log_free_connection);
}
