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
#include <stdio.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char *argv[]) 
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char temptext[64] = {0,};
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	int len=64;
	
 	FILE *fp;

	printf("Usage: %s \n", argv[1]);
	printf("Usage: %s \n", argv[2]);



	fp = fopen(argv[2], "r");
	
	fgets(temptext,sizeof(temptext),fp);
	
	


	if(argv == "-e"){
		
		fp_out = fopen("encrypted.txt", "w");

		res = TEEC_InitializeContext(NULL, &ctx);
		res = TEEC_OpenSession(&ctx, &sess, &uuid,
				       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = temptext;
		op.params[0].tmpref.size = len;

		memcpy(op.params[0].tmpref.buffer, temptext, len);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
					 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);

		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		printf("암호화된 문자열 : %s\n", ciphertext);
		
		fputc(ciphertext,fp_out);

		printf("텍스트 저장완료 : %s\n", ciphertext);

		TEEC_CloseSession(&sess);
		TEEC_FinalizeContext(&ctx);

	}
	else if(argv == "-d"){

		fp_out = fopen("decrypted.txt", "w");

		res = TEEC_InitializeContext(NULL, &ctx);
		res = TEEC_OpenSession(&ctx, &sess, &uuid,
				       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = temptext;
		op.params[0].tmpref.size = len;

		memcpy(op.params[0].tmpref.buffer, temptext, len);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
					 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);

		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		printf("복호화된 문자열 : %s\n", ciphertext);
		
		fputc(ciphertext,fp_out);

		printf("텍스트 저장완료 : %s\n", ciphertext);

		TEEC_CloseSession(&sess);
		TEEC_FinalizeContext(&ctx);
	}

	return 0;
}
