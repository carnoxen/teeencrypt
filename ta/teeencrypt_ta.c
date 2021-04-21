/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <ctype.h>

#include "teeencrypt_ta.h"

// caesar start

typedef struct __rsa_session rsa_session;

struct __rsa_session {
	TEE_OperationHandle op_handle;	/* RSA operation */
	TEE_ObjectHandle key_handle; /* Key handle */
};

static unsigned char caesar_key = -1;
static const size_t LETTERS = 'z' - 'a' + 1;

static unsigned char enc_letter(unsigned char c) {
	if (islower(c)) {
		return ((c - 'a' + caesar_key) % LETTERS) + 'a';
	}
	else if (isupper(c)){
		return ((c - 'A' + caesar_key) % LETTERS) + 'A';
	}
	return c;
}

static unsigned char dec_letter(unsigned char c) {
	if (islower(c)) {
		return ((c - 'a' - caesar_key + LETTERS) % LETTERS) + 'a';
	}
	else if (isupper(c)){
		return ((c - 'A' - caesar_key + LETTERS) % LETTERS) + 'A';
	}
	return c;
}

TEE_Result caesar_create_key()
{
	TEE_GenerateRandom(&caesar_key, sizeof(caesar_key));
	caesar_key = (caesar_key % (LETTERS - 1)) + 1;

	DMSG("======================== Caesar: Key Generation ========================\n");
	DMSG("Key :  %d\n", caesar_key);

	return TEE_SUCCESS;
}

TEE_Result caesar_encrypt(TEE_Param params[4])
{
	char* in = (char*) params[0].memref.buffer;
	size_t in_len = params[0].memref.size;
	char* out = (char*) params[1].memref.buffer;
	size_t out_len = params[1].memref.size;

	for(size_t i = 0; i < in_len - 1; i++){
		out[i] = enc_letter(in[i]);
	}

	out[out_len - 1] = caesar_key + 'A';

	DMSG("======================== Caesar: Encryption ========================\n");
	DMSG("Plaintext :  %s\n", in);
	DMSG("Ciphertext :  %s\n", out);

	return TEE_SUCCESS;
}

TEE_Result caesar_decrypt(TEE_Param params[4])
{
	char* in = (char*) params[0].memref.buffer;
	size_t in_len = params[0].memref.size;
	char* out = (char*) params[1].memref.buffer;
	size_t out_len = params[1].memref.size;

	caesar_key = in[in_len - 2] - 'A';

	for(size_t i = 0; i < in_len - 2; i++){
		out[i] = dec_letter(in[i]);
	}

	out[out_len - 2] = '\n';

	DMSG("======================== Caesar: Decryption ========================\n");
	DMSG("Ciphertext :  %s", in);
	DMSG("Plaintext :  %s", out);

	return TEE_SUCCESS;
}

// caesar end

// rsa start

TEE_Result prepare_rsa_operation(TEE_OperationHandle *handle, uint32_t alg, TEE_OperationMode mode, TEE_ObjectHandle key) {
	TEE_ObjectInfo key_info;
	TEE_Result ret = TEE_GetObjectInfo1(key, &key_info);
	if (ret != TEE_SUCCESS) {
		EMSG("\nTEE_GetObjectInfo1: %#\n" PRIx32, ret);
		return ret;
	}

	DMSG("\n==== allocate operation\n");
	ret = TEE_AllocateOperation(handle, alg, mode, key_info.keySize);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to alloc operation handle : 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Operation allocated successfully. ==========\n");

	ret = TEE_SetOperationKey(*handle, key);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to set key : 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Operation key already set. ==========\n");

	return ret;
}

TEE_Result check_params(uint32_t param_types) {
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE
		);

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	return TEE_SUCCESS;
}

TEE_Result rsa_create_key_pair(void *session) {
	TEE_Result ret;
	size_t key_size = RSA_KEY_SIZE;
	struct __rsa_session *sess = (struct __rsa_session *)session;
	
	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to alloc transient object handle: 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Transient object allocated. ==========\n");

	ret = TEE_GenerateKey(sess->key_handle, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		EMSG("\nGenerate key failure: 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Keys generated. ==========\n");
	return ret;
}

TEE_Result rsa_encrypt(void *session, uint32_t param_types, TEE_Param params[4]) {
	TEE_Result ret;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
	struct __rsa_session *sess = (struct __rsa_session *)session;

	if (check_params(param_types) != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	void *plain_txt = params[0].memref.buffer;
	size_t plain_len = params[0].memref.size;
	void *cipher = params[1].memref.buffer;
	size_t cipher_len = params[1].memref.size;

	DMSG("\n========== Preparing encryption operation ==========\n");
	ret = prepare_rsa_operation(&sess->op_handle, rsa_alg, TEE_MODE_ENCRYPT, 
		sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to prepare RSA operation: 0x%x\n", ret);
		goto err;
	}

	DMSG("\nData to encrypt: %s\n", (char *) plain_txt);
	ret = TEE_AsymmetricEncrypt(sess->op_handle, (TEE_Attribute *)NULL, 0,
					plain_txt, plain_len, cipher, &cipher_len);					
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to encrypt the passed buffer: 0x%x\n", ret);
		goto err;
	}
	DMSG("\nEncrypted data: %s\n", (char *) cipher);
	DMSG("\n========== Encryption successfully ==========\n");
	return ret;

err:
	TEE_FreeOperation(sess->op_handle);
	TEE_FreeOperation(sess->key_handle);
	return ret;
}

// static TEE_Result rsa_decrypt(void *session, uint32_t param_types, TEE_Param params[4]) {
// 	TEE_Result ret;
// 	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
// 	struct __rsa_session *sess = (struct __rsa_session *)session;

// 	if (check_params(param_types) != TEE_SUCCESS)
// 		return TEE_ERROR_BAD_PARAMETERS;

// 	void *plain_txt = params[1].memref.buffer;
// 	size_t plain_len = params[1].memref.size;
// 	void *cipher = params[0].memref.buffer;
// 	size_t cipher_len = params[0].memref.size;

// 	DMSG("\n========== Preparing decryption operation ==========\n");
// 	ret = prepare_rsa_operation(&sess->op_handle, rsa_alg, TEE_MODE_DECRYPT, sess->key_handle);
// 	if (ret != TEE_SUCCESS) {
// 		EMSG("\nFailed to prepare RSA operation: 0x%x\n", ret);
// 		goto err;
// 	}

// 	DMSG("\nData to decrypt: %s\n", (char *) cipher);
// 	ret = TEE_AsymmetricDecrypt(sess->op_handle, (TEE_Attribute *)NULL, 0,
// 				cipher, cipher_len, plain_txt, &plain_len);
// 	if (ret != TEE_SUCCESS) {
// 		EMSG("\nFailed to decrypt the passed buffer: 0x%x\n", ret);
// 		goto err;
// 	}
// 	DMSG("\nDecrypted data: %s\n", (char *) plain_txt);
// 	DMSG("\n========== Decryption successfully ==========\n");
// 	return ret;

// err:
// 	TEE_FreeOperation(sess->op_handle);
// 	TEE_FreeTransientObject(sess->key_handle);
// 	return ret;
// }

// rsa end

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t __maybe_unused param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **session)
{
	rsa_session *sess = TEE_Malloc(sizeof(*sess), 0);
	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;

	sess->key_handle = TEE_HANDLE_NULL;
	sess->op_handle = TEE_HANDLE_NULL;

	*session = (void *)sess;
	DMSG("\nSession %p: newly allocated\n", *session);

	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void *session)
{
	/* Get ciphering context from session ID */
	DMSG("Session %p: release session", session);
	rsa_session* sess = (rsa_session *)session;

	/* Release the session resources
	   These tests are mandatories to avoid PANIC TA (TEE_HANDLE_NULL) */
	if (sess->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->key_handle);
	if (sess->op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(sess->op_handle);
	TEE_Free(sess);
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *session, uint32_t cmd,
			uint32_t __maybe_unused param_types, TEE_Param params[4])
{
	switch (cmd) {
	case CAESAR_GENKEY:
		return caesar_create_key();
	case CAESAR_ENC:
		return caesar_encrypt(params);
	case CAESAR_DEC:
		return caesar_decrypt(params);

	case RSA_GENKEY:
		return rsa_create_key_pair(session);
	case RSA_ENC:
		return rsa_encrypt(session, param_types, params);
	// case RSA_DEC:
	// 	return rsa_decrypt(session, param_types, params);

	default:
		EMSG("Command ID 0x%x is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
