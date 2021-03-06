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

// common start

static TEE_Result check_params(uint32_t param_types) {
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE
		);

	DMSG("> Checking parameters...\n");
	/* Safely get the invocation parameters */
	if (param_types != exp_param_types) {
		EMSG("!> Mismatched parameters\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	return TEE_SUCCESS;
}

// common end

// caesar start

static const size_t CAESAR_ROOT = 'A'; // caesar root key
static unsigned char caesar_key = -1;
static const size_t LETTERS = 'z' - 'a' + 1; // number of alphabets

// foward letter
static unsigned char enc_letter(unsigned char c) {
	if (islower(c)) {
		return ((c - 'a' + caesar_key) % LETTERS) + 'a';
	}
	else if (isupper(c)){
		return ((c - 'A' + caesar_key) % LETTERS) + 'A';
	}
	return c;
}

// back letter
static unsigned char dec_letter(unsigned char c) {
	if (islower(c)) {
		return ((c - 'a' + (LETTERS - caesar_key)) % LETTERS) + 'a';
	}
	else if (isupper(c)){
		return ((c - 'A' + (LETTERS - caesar_key)) % LETTERS) + 'A';
	}
	return c;
}

// key range: 1 ~ 25
static TEE_Result caesar_create_key(void) {
	TEE_GenerateRandom(&caesar_key, sizeof(caesar_key));
	caesar_key = (caesar_key % (LETTERS - 1)) + 1;
	return TEE_SUCCESS;
}

static TEE_Result caesar_encrypt(TEE_Param params[4]) {
	TEE_Result res = caesar_create_key();
	if (TEE_SUCCESS != res) {
		return res;
	}

	DMSG("> Caesar: Key Generated \n");
	DMSG(">> Key :  %d\n", caesar_key);

	char* in = (char*) params[0].memref.buffer;
	size_t in_len = strlen(params[0].memref.buffer);
	char* out = (char*) params[1].memref.buffer;

	for(size_t i = 0; i < in_len - 1; i++){
		out[i] = enc_letter(in[i]);
	}

	out[in_len - 1] = caesar_key + CAESAR_ROOT;
	out[in_len] = '\n';

	DMSG("> Caesar: Encryption\n");
	DMSG(">> Plaintext :  %s\n", in);
	DMSG(">> Ciphertext :  %s\n", out);

	return res;
}

static TEE_Result caesar_decrypt(TEE_Param params[4]) {
	char* in = (char*) params[0].memref.buffer;
	size_t in_len = strlen(params[0].memref.buffer);
	char* out = (char*) params[1].memref.buffer;

	caesar_key = in[in_len - 2] - CAESAR_ROOT;

	DMSG("> Caesar: Key Retrived \n");
	DMSG(">> Key :  %d\n", caesar_key);

	for(size_t i = 0; i < in_len - 2; i++){
		out[i] = dec_letter(in[i]);
	}

	out[in_len - 2] = '\n';
	out[in_len - 1] = '\0';

	DMSG("> Caesar: Decryption\n");
	DMSG(">> Ciphertext :  %s", in);
	DMSG(">> Plaintext :  %s", out);

	return TEE_SUCCESS;
}

// caesar end

// rsa start

typedef struct __rsa_session {
	TEE_OperationHandle op_handle;	/* RSA operation */
	TEE_ObjectHandle key_handle; /* Key handle */
} RSASession;

static TEE_Result prepare_rsa_operation(TEE_OperationHandle *handle, uint32_t alg, 
					TEE_OperationMode mode, TEE_ObjectHandle key) {
	TEE_ObjectInfo key_info;
	TEE_Result res = TEE_GetObjectInfo1(key, &key_info);
	if (res != TEE_SUCCESS) {
		EMSG("!> TEE_GetObjectInfo1: %#\n" PRIx32, res);
		return res;
	}

	res = TEE_AllocateOperation(handle, alg, mode, key_info.keySize);
	if (res != TEE_SUCCESS) {
		EMSG("!> Failed to alloc operation handle : 0x%x\n", res);
		return res;
	}
	DMSG("> Operation allocated successfully.\n");

	res = TEE_SetOperationKey(*handle, key);
	if (res != TEE_SUCCESS) {
		EMSG("!> Failed to set key : 0x%x\n", res);
		return res;
	}
	DMSG("> Operation key already set.\n");

	return res;
}

static TEE_Result rsa_create_key_pair(void *session) {
	uint32_t key_size = RSA_KEY_SIZE;
	RSASession *sess = (RSASession *)session;
	
	TEE_Result res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &(sess->key_handle));
	if (res != TEE_SUCCESS) {
		EMSG("!> Failed to alloc transient object handle: 0x%x\n", res);
		return res;
	}
	DMSG("> Transient object allocated.\n");

	res = TEE_GenerateKey(sess->key_handle, key_size, (TEE_Attribute *)NULL, 0);
	if (res != TEE_SUCCESS) {
		EMSG("!> Generate key failure: 0x%x\n", res);
		return res;
	}
	DMSG("> Keys generated.\n");
	return res;
}

static TEE_Result rsa_encrypt(void *session, uint32_t param_types, TEE_Param params[4]) {
	TEE_Result res = rsa_create_key_pair(session);
	if (res != TEE_SUCCESS) {
		return res;
	}

	RSASession *sess = (RSASession *)session;

	void *plain_txt = params[0].memref.buffer;
	uint32_t plain_len = params[0].memref.size;
	void *cipher = params[1].memref.buffer;
	uint32_t cipher_len = params[1].memref.size;

	DMSG("> Preparing encryption operation...\n");
	res = prepare_rsa_operation(&(sess->op_handle), TEE_ALG_RSAES_PKCS1_V1_5, 
				    TEE_MODE_ENCRYPT, sess->key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("!> Failed to prepare RSA operation: 0x%x\n", res);
		goto err;
	}

	res = TEE_AsymmetricEncrypt(sess->op_handle, (TEE_Attribute *)NULL, 0,
					plain_txt, plain_len, cipher, &cipher_len);					
	if (res != TEE_SUCCESS) {
		EMSG("!> Failed to encrypt the passed buffer: 0x%x\n", res);
		goto err;
	}

	DMSG("> Encryption successfully\n");
	DMSG(">> Data to encrypt: %s\n", (char *) plain_txt);
	DMSG(">> Encrypted data: %s\n", (char *) cipher);
	return res;

err:
	TEE_FreeOperation(sess->op_handle);
	TEE_FreeOperation(sess->key_handle);
	return res;
}

// rsa end

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void) {
	DMSG("has been called");
	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void) {
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
		void **session) {
	RSASession *sess = TEE_Malloc(sizeof(*sess), 0);
	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;

	sess->key_handle = TEE_HANDLE_NULL;
	sess->op_handle = TEE_HANDLE_NULL;

	*session = (void *)sess;
	DMSG("> Session %p: newly allocated\n", *session);

	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void *session) {
	/* Get ciphering context from session ID */
	DMSG("> Session %p: release session", session);
	RSASession* sess = (RSASession *)session;

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
TEE_Result TA_InvokeCommandEntryPoint(void *session, uint32_t cmd,
			uint32_t param_types, TEE_Param params[4]) {
	if (check_params(param_types) != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (cmd) {
	case CAESAR_ENC:
		return caesar_encrypt(params);
	case CAESAR_DEC:
		return caesar_decrypt(params);

	case RSA_ENC:
		return rsa_encrypt(session, param_types, params);
	// case RSA_DEC:
	// 	return rsa_decrypt(session, param_types, params);

	default:
		EMSG("!> Command ID 0x%x is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
