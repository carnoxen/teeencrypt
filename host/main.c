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
#include <stdlib.h>
#include <limits.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>
#include "teeencrypt_ta.h"

// common start

typedef struct __ta_attrs {
	TEEC_Context context;
	TEEC_Session session;
	TEEC_Operation operation;
} Attributes;

typedef TEEC_TempMemoryReference Data;

#define PARAM_SIZE (TEEC_CONFIG_PAYLOAD_REF_COUNT - 2U)

static TEEC_Result prepare_ta_session(Attributes *attrsp) {
	TEEC_UUID uuid = TA_TEEENCRYPT_UUID;
	uint32_t origin;

	/* Initialize a context connecting us to the TEE */
	TEEC_Result res = TEEC_InitializeContext(NULL, &(attrsp->context));
	if (res != TEEC_SUCCESS) {
		errx(1, "!> TEEC_InitializeContext failed with code 0x%x\n", res);
		return res;
	}

	/* Open a session with the TA */
	res = TEEC_OpenSession(&(attrsp->context), &(attrsp->session), &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS) {
		errx(1, "!> TEEC_Opensession failed with code 0x%x origin 0x%x\n", 
			res, origin);
		return res;
	}

	return res;
}

static size_t get_file_size(FILE* fp) {
	fseek(fp, 0, SEEK_END);
	size_t fileSize = ftell(fp);
	rewind(fp);

	return fileSize;
}

static TEEC_Result send_to_ta(Attributes *attrsp, uint32_t command) {
	uint32_t origin;
	TEEC_Result res = TEEC_InvokeCommand(&(attrsp->session), command, 
		&(attrsp->operation), &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "!> TEEC_InvokeCommand(%d) failed 0x%x origin 0x%x\n",
			command, res, origin);

	return res;
}

static void check_extention(char* extention, char* lookup) {
	if (strcmp(extention, lookup)) {
		perror("!> It's not an encrypted file");
		exit(1);
	}
}

static void prepare_op(TEEC_Operation *opp, Data data[]) {
	memset(opp, 0, sizeof(*opp));

	opp->paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_NONE,
		TEEC_NONE
	);

	for (size_t i = 0; i < PARAM_SIZE; ++i) {
		opp->params[i].tmpref = data[i];
	}
}

static void terminate_tee_session(Attributes *attrsp) {
	TEEC_CloseSession(&(attrsp->session));
	TEEC_FinalizeContext(&(attrsp->context));
}

int main(int argc, char* argv[]) {
	if (4 != argc) {
		perror("> complete 4 words (ex. teeencrypt -e data.txt caesar)");
		return 1;
	}

	Attributes attrs; TEEC_Result result = TEEC_ERROR_BAD_STATE;
	prepare_ta_session(&attrs);

	FILE* fp = fopen(argv[2], "r");
	if (fp == NULL) {
		perror("!> file not found");
		return 1;
	}
	puts("> file detected");

	size_t fileSize = get_file_size(fp), outputSize = fileSize + 2;
	void *input = calloc(fileSize + 2, 1), *output = calloc(fileSize + 2, 1);
	fread(input, 1, fileSize, fp);

	char name[PATH_MAX], nameModified[PATH_MAX];
	realpath(argv[2], name);
	strcpy(nameModified, name);

	Data data[PARAM_SIZE] = {
		(Data) {input, fileSize + 2},
		(Data) {output, fileSize + 2}
	};
	prepare_op(&(attrs.operation), data);

	if (!strcmp(argv[3], "caesar")) {
		if (!strcmp(argv[1], "-e")) {
			puts("> Caesar: encryption start");
			strcat(nameModified, ".caesar");
			result = send_to_ta(&attrs, CAESAR_ENC);
			puts("> Caesar: encryption complete");
			++fileSize;
		}
		else if (!strcmp(argv[1], "-d")) {
			puts("> Caesar: decryption start");
			char *start = strrchr(nameModified, '.');
			check_extention(start, ".caesar");
			*start = '\0';
			result = send_to_ta(&attrs, CAESAR_DEC);
			puts("> Caesar: decryption complete");
			--fileSize;
		}
		else{
			goto no_option;
		}
	}
	else if (!strcmp(argv[3], "rsa")) {
		if (!strcmp(argv[1], "-e")) {
			puts("> RSA: encryption start");
			strcat(nameModified, ".rsa");
			data[0] = (Data) {realloc(input, RSA_MAX_PLAIN_LEN_1024), RSA_MAX_PLAIN_LEN_1024};
			data[1] = (Data) {realloc(output, RSA_CIPHER_LEN_1024), RSA_CIPHER_LEN_1024};
			prepare_op(&(attrs.operation), data);
			result = send_to_ta(&attrs, RSA_ENC);
			puts("> RSA: encryption complete");
			fileSize = RSA_CIPHER_LEN_1024;
			input = data[0].buffer;
			output = data[1].buffer;
		}
		// else if (!strcmp(argv[1], "-d")) {
		// }
		else{
			goto no_option;
		}
	}
	else {
no_option:
		perror("!> no option found");
	}

	if (TEEC_SUCCESS != result) {
		return 1;
	}

	fp = freopen(name, "w", fp);
	fwrite(output, 1, fileSize, fp);
	rename(name, nameModified);
	fclose(fp);
	terminate_tee_session(&attrs);

	printf("input: %s\n", (char *)input);
	printf("output: %s\n", (char *)output);

	return 0;
}
