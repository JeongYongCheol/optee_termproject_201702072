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

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

#define NAME_MAX	255
#define DEC_ARC_NUM	4
#define RSA_ARC_NUM	4

/* Read a file with string contents */
char* OpenFileReadStrContent(char *filename) 
{
	char *buffer;	
	int size;

	FILE* fp = fopen(filename, "r");
	
	if(fp == NULL) return NULL;

	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	
	buffer = malloc(size+1);
	memset(buffer, 0, size + 1);

	fseek(fp, 0, SEEK_SET);
	fread(buffer, size, 1, fp);

	fclose(fp);
	
	return buffer;
}

/* Read a file with int contents */
int OpenFileReadIntContent(char *filename)
{
	int content;

	FILE* fp = fopen(filename, "r");
	
	if(fp == NULL) return 0;

	fscanf(fp, "%d", &content);
	
	fclose(fp);

	return content;
}

/* Write a file with string contents */
int WriteFileStrContent(char *filename, char *content)
{
	FILE *fp = fopen(filename, "w");
	
	if(fp == NULL) return 0;
	
	fputs(content, fp);
	
	fclose(fp);

	return 1;
}

/* Write a file with string contents */
int WriteFileIntContent(char *filename, int content)
{
	FILE *fp = fopen(filename, "w");
	
	if(fp == NULL) return 0;
	
	fprintf(fp, "%d\n", content);
	
	fclose(fp);

	return 1;
}

int main(int arc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char *plaintext;
	char *ciphertext;
	int len;
	int key_enc;	

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);

	if(!strcmp(argv[1], "-e")) {
		printf("========================Encryption========================\n");
		
		if((plaintext = OpenFileReadStrContent(argv[2])) == NULL) return -1;
		len = strlen(plaintext);

		op.params[0].tmpref.buffer = plaintext;
		op.params[0].tmpref.size = len;
		memcpy(op.params[0].tmpref.buffer, plaintext, len);

		op.params[1].value.a = 0;

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
				 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);

		/* Storing each data brought form TA */
		ciphertext = op.params[0].tmpref.buffer;
		key_enc = op.params[1].value.a;

		/* Generate an encrypted text file */
		char *filename = argv[2];
		char filename_enc[NAME_MAX] = {0,};
		strncpy(filename_enc, filename, strlen(filename)-4);
		strcat(filename_enc, "_enc.txt");
		WriteFileStrContent(filename_enc, ciphertext);

		/* Generate an encrypted key file */
		char filename_key[NAME_MAX] = {0,};
		strncpy(filename_key, filename, strlen(filename)-4);
		strcat(filename_key, "_key.txt");
		WriteFileIntContent(filename_key, key_enc);

		printf("Ciphertext file & Key file creation Success!\n");
	}
	else if(!strcmp(argv[1], "-d") && arc == DEC_ARC_NUM) {
		printf("========================Decryption========================\n");
		
		if((ciphertext = OpenFileReadStrContent(argv[2])) == NULL) return -1;
		len = strlen(ciphertext);

		op.params[0].tmpref.buffer = ciphertext;
		op.params[0].tmpref.size = len;
		memcpy(op.params[0].tmpref.buffer, ciphertext, len);

		if(!(key_enc = OpenFileReadIntContent(argv[3]))) return -1;
		op.params[1].value.a = key_enc;
		
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
				 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);

		/* Storing each data brought form TA */
		plaintext = op.params[0].tmpref.buffer;

		/* Generate an encrypted text file */
		char *filename = argv[2];
		char filename_dec[NAME_MAX] = {0,};
		strncpy(filename_dec, filename, strlen(filename)-4);
		strcat(filename_dec, "_dec.txt");
		WriteFileStrContent(filename_dec, plaintext);

		printf("Plaintext file creation Success!\n");
	}

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
