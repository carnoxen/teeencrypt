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

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>
#include "teeencrypt_ta.h"

// common start

typedef struct __ta_attrs {
	TEEC_Context ctx;
	TEEC_Session sess;
} ta_attrs;

typedef struct __word {
	char* buffer;
	size_t size;
} word;

// common end

// caesar start

void caesar_gen_keys(ta_attrs *ta) {
	TEEC_Result res = TEEC_InvokeCommand(&ta->sess, CAESAR_GENKEY, NULL, NULL);
	if (res != TEEC_SUCCESS)
		errx(1, "!> TEEC_InvokeCommand(CAESAR_GENKEY) failed %#x\n", res);
    
	puts("> Keys already generated.");
}

void caesar_encrypt(ta_attrs *ta, TEEC_Operation* op) {
	puts("> CAESAR ENCRYPT CA SIDE");
    
	uint32_t origin;

	TEEC_Result res = TEEC_InvokeCommand(&ta->sess, CAESAR_ENC, op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "!> TEEC_InvokeCommand(CAESAR_ENC) failed 0x%x origin 0x%x\n",
			res, origin);

	printf("> The text sent was encrypted: %s\n", 
		(char *)op->params[1].tmpref.buffer);
}

void caesar_decrypt(ta_attrs *ta, TEEC_Operation* op) {
	puts("> CAESAR DECRYPT CA SIDE");

	uint32_t origin;

	TEEC_Result res = TEEC_InvokeCommand(&ta->sess, CAESAR_DEC, op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "!> TEEC_InvokeCommand(CAESAR_DEC) failed 0x%x origin 0x%x\n",
			res, origin);

	printf("> The text sent was decrypted: %s\n", 
		(char *)op->params[1].tmpref.buffer);
}

// caesar end

// rsa start

void rsa_gen_keys(ta_attrs *ta) {
	TEEC_Result res = TEEC_InvokeCommand(&ta->sess, RSA_GENKEY, NULL, NULL);
	if (res != TEEC_SUCCESS)
		errx(1, "!> TEEC_InvokeCommand(RSA_GENKEYS) failed %#x\n", res);

	puts("> Keys already generated.");
}

void rsa_encrypt(ta_attrs *ta, TEEC_Operation* op) {
	puts("> RSA ENCRYPT CA SIDE");

	uint32_t origin;
	TEEC_Result res = TEEC_InvokeCommand(&ta->sess, RSA_ENC, op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "!> TEEC_InvokeCommand(TA_RSA_CMD_ENCRYPT) failed 0x%x origin 0x%x\n",
			res, origin);

	printf("> The text sent was encrypted: %s\n", (char *)op->params[1].tmpref.buffer);
}

// void rsa_decrypt(ta_attrs *ta, TEEC_Operation* op)
// {
// 	puts("\n============ RSA DECRYPT CA SIDE ============");

// 	uint32_t origin;

// 	TEEC_Result res = TEEC_InvokeCommand(&ta->sess, RSA_DEC, 
// 		op, &origin);
// 	if (res != TEEC_SUCCESS)
// 		errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_DECRYPT) failed 0x%x origin 0x%x\n",
// 			res, origin);

// 	printf("\nThe text sent was decrypted: %s\n", (char *)op->params[1].tmpref.buffer);
// }

// rsa end

static size_t get_file_size(FILE* fp) {
	fseek(fp, 0, SEEK_END);
	size_t fileSize = ftell(fp);
	rewind(fp);

	return fileSize;
}

static void prepare_ta_session(ta_attrs *ta) {
	TEEC_UUID uuid = TA_TEEENCRYPT_UUID;
	uint32_t origin;

	/* Initialize a context connecting us to the TEE */
	TEEC_Result res = TEEC_InitializeContext(NULL, &ta->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "!> TEEC_InitializeContext failed with code 0x%x\n", res);

	/* Open a session with the TA */
	res = TEEC_OpenSession(&ta->ctx, &ta->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "!> TEEC_Opensession failed with code 0x%x origin 0x%x\n", 
			res, origin);
}

static void terminate_tee_session(ta_attrs *ta) {
	TEEC_CloseSession(&ta->sess);
	TEEC_FinalizeContext(&ta->ctx);
}

static void prepare_op(TEEC_Operation *op, word data[]) {
	memset(op, 0, sizeof(*op));

	op->paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_NONE,
		TEEC_NONE);

	for (size_t i = 0; i < TEEC_CONFIG_PAYLOAD_REF_COUNT - 2; ++i) {
		op->params[i].tmpref.buffer = data[i].buffer;
		op->params[i].tmpref.size = data[i].size;
	}
}

int main(int argc, char* argv[]) {
	if (4 != argc) {
		perror("> complete 4 words (ex. teeencrypt -e data.txt caesar)");
		return 1;
	}

	ta_attrs ta;
	TEEC_Operation op;

	prepare_ta_session(&ta);

	FILE* fp = fopen(argv[2], "r+");
	if (fp == NULL) {
		perror("!> file not found");
		return 1;
	}

	size_t fileSize = get_file_size(fp);
	puts("> file detected");

	word data[TEEC_CONFIG_PAYLOAD_REF_COUNT] = {NULL, };
	char fileName[PATH_MAX];
	realpath(argv[2], fileName);
	char modifiedFileName[PATH_MAX];

	if (!strcmp(argv[3], "caesar")) {
		data[0] = (word) {(char*) calloc(fileSize, 1), fileSize};
		data[1] = (word) {(char*) calloc(fileSize, 1), fileSize};

		prepare_op(&op, data);
		fread(data[0].buffer, 1, data[0].size, fp);

		if (!strcmp(argv[1], "-e")) {
			caesar_gen_keys(&ta);
			caesar_encrypt(&ta, &op);

			fp = freopen(fileName, "w", fp);
			fwrite(data[1].buffer, 1, data[1].size, fp);
			fputc('\n', fp);

			strcpy(modifiedFileName, fileName);
			strcat(modifiedFileName, ".caesar");
		}
		else if (!strcmp(argv[1], "-d")) {
			caesar_decrypt(&ta, &op);
			
			fp = freopen(fileName, "w", fp);
			fwrite(data[1].buffer, 1, data[1].size - 1, fp);

			strcpy(modifiedFileName, fileName);
			char* ptr = strrchr(modifiedFileName, '.');
			if (strcmp(ptr, ".caesar")) {
				perror("!> ERROR: Not encrypted file(.caesar)");
				return 1;
			}
			memset(ptr, 0, strlen(ptr));
		}
		else{
			goto no_option;
		}
		rename(fileName, modifiedFileName);
	}
	else if (!strcmp(argv[3], "rsa")) {
		if (!strcmp(argv[1], "-e")) {
			data[0] = (word) {(char*) calloc(RSA_MAX_PLAIN_LEN_1024, 1), RSA_MAX_PLAIN_LEN_1024};
			data[1] = (word) {(char*) calloc(RSA_CIPHER_LEN_1024, 1), RSA_CIPHER_LEN_1024};

			prepare_op(&op, data);
			fread(data[0].buffer, 1, data[0].size, fp);

			rsa_gen_keys(&ta);
			rsa_encrypt(&ta, &op);

			fp = freopen(data[2].buffer, "w", fp);
			fwrite(data[1].buffer, 1, data[1].size, fp);

			strcpy(modifiedFileName, fileName);
			strcat(modifiedFileName, ".rsa");
		}
		// else if (!strcmp(argv[1], "-d")) {
		// 	word in = {(char*) calloc(RSA_CIPHER_LEN_1024, 1), RSA_CIPHER_LEN_1024};
		// 	word out = {(char*) calloc(RSA_MAX_PLAIN_LEN_1024, 1), RSA_MAX_PLAIN_LEN_1024};

		// 	prepare_op(&op, &in, &out);
		// 	fread(in.buffer, 1, in.length, fp);
		// 	//
		// 	rsa_decrypt(&ta, &op);
		// 	fp = freopen("/root/decrypted_rsa.txt", "w", fp);
		// 	fwrite(out.buffer, 1, strlen(out.buffer), fp);
		// }
		else{
			goto no_option;
		}
		rename(fileName, modifiedFileName);
	}
	else {
no_option:
		puts("!> no option found");
	}

	fclose(fp);
	terminate_tee_session(&ta);

	return 0;
}
