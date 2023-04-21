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
#include <inttypes.h>
#include <time.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <hello_world_ta.h>

/* For Socket */
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* For AES */
#define AES_TEST_BUFFER_SIZE	4096
#define AES_TEST_KEY_SIZE	16
#define AES_BLOCK_SIZE		16

#define DECODE			0
#define ENCODE			1

struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

/* TEE Prepare and Close */
void prepare_tee_session(struct test_ctx *ctx)
{
	TEEC_UUID uuid = TA_HELLO_WORLD_UUID;
	uint32_t origin;
	TEEC_Result res;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/* Open a session with the TA */
	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, origin);
}

void terminate_tee_session(struct test_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

/* AES functions */
void prepare_aes(struct test_ctx *ctx, int encode)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_NONE);

	op.params[0].value.a = TA_AES_ALGO_CTR;
	op.params[1].value.a = TA_AES_SIZE_128BIT;
	op.params[2].value.a = encode ? TA_AES_MODE_ENCODE :
					TA_AES_MODE_DECODE;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_PREPARE,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(PREPARE) failed 0x%x origin 0x%x",
			res, origin);
}

void gen_key(struct test_ctx *ctx, size_t key_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].value.a = key_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_GEN_KEY,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_KEY) failed 0x%x origin 0x%x",
			res, origin);
}

void set_key(struct test_ctx *ctx)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_SET_KEY,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_KEY) failed 0x%x origin 0x%x",
			res, origin);
}

void set_iv(struct test_ctx *ctx, char *iv, size_t iv_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					  TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = iv;
	op.params[0].tmpref.size = iv_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_SET_IV,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_IV) failed 0x%x origin 0x%x",
			res, origin);
}

void cipher_buffer(struct test_ctx *ctx, char *buf, size_t sz, int *result)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	
	op.params[0].tmpref.buffer = buf;
	op.params[0].tmpref.size = sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_CIPHER,
				 &op, &origin);
	
	*result = op.params[0].tmpref.size;
}

void create_sign(struct test_ctx *ctx, char *hash, uint32_t *hash_len,
						char *sign, uint32_t *sign_len)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = hash;
	op.params[0].tmpref.size = *hash_len;
	
	res = TEEC_InvokeCommand(&ctx->sess, TA_RSA_CMD_HASH,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(HASH) failed 0x%x origin 0x%x",
			res, origin);
	
	*hash_len = op.params[0].tmpref.size;
	
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = hash;
	op.params[0].tmpref.size = *hash_len;
	
	op.params[1].tmpref.buffer = sign;
	op.params[1].tmpref.size = *sign_len;
	
	res = TEEC_InvokeCommand(&ctx->sess, TA_RSA_CMD_SIGN,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SIGN) failed 0x%x origin 0x%x",
			res, origin);
	else printf("Signature Created!\n");
	
	*sign_len = op.params[1].tmpref.size;
}

void verify_sign(struct test_ctx *ctx, char *hash, uint32_t hash_len, char *sign, uint32_t sign_len)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = hash;
	op.params[0].tmpref.size = hash_len;
	
	op.params[1].tmpref.buffer = sign;
	op.params[1].tmpref.size = sign_len;
	
	res = TEEC_InvokeCommand(&ctx->sess, TA_RSA_CMD_VERIFY,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(VERIFY) failed 0x%x origin 0x%x",
			res, origin);
	else printf("Verify Succeed!\n");
}

void rsa_encrypt(struct test_ctx *ctx, char *ciph, uint32_t *ciph_len)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	
	op.params[0].tmpref.buffer = ciph;
	op.params[0].tmpref.size = *ciph_len;
	
	res = TEEC_InvokeCommand(&ctx->sess, TA_RSA_CMD_ENCRYPT,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(ENCRYPT) failed 0x%x origin 0x%x",
			res, origin);
			
	*ciph_len = op.params[0].tmpref.size;
}

void rsa_decrypt(struct test_ctx *ctx, char *ciph, uint32_t ciph_len)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	
	op.params[0].tmpref.size = ciph_len;
	op.params[0].tmpref.buffer = malloc(ciph_len);
	memmove(op.params[0].tmpref.buffer, ciph, ciph_len);
	
	res = TEEC_InvokeCommand(&ctx->sess, TA_RSA_CMD_DECRYPT,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(DECRYPT) failed 0x%x origin 0x%x",
			res, origin);
}

int main(int argc, char *argv[])
{
	struct test_ctx ctx;
	char iv[AES_BLOCK_SIZE];
	char ciph[AES_TEST_BUFFER_SIZE];
	
	printf("Set Random Initial Vector\n");
	srand(time(NULL));
	int i;
	for(i=0; i<AES_BLOCK_SIZE; i++){
		iv[i] = rand()%93+33;
	}
	printf("iv: %s\n", iv);
	
	char hash[64];
	uint32_t hash_len = sizeof(hash);
	char sign[256];
	uint32_t sign_len = sizeof(sign);
	char rsa_ciph[256];
	uint32_t rsa_ciph_size = sizeof(rsa_ciph);
	
	printf("Prepare session with the TA\n");
	prepare_tee_session(&ctx);
	
	/* Create Signature */
	
	printf("Creatie Signature\n");
	create_sign(&ctx, hash, &hash_len, sign, &sign_len);
	
	printf("hash: %s\n", hash);
	printf("hash_len = %" PRId32 "\n", hash_len);
	char hash_size[] = { hash_len/100+'0', (hash_len%100)/10+'0', (hash_len%10)+'0' };
	printf("hash_size = %s\n", hash_size);
	printf("sign: %s\n", sign);
	printf("sign_len = %" PRId32 "\n", sign_len);
	char sign_size[] = { sign_len/100+'0', (sign_len%100)/10+'0', (sign_len%10)+'0' };
	printf("sign_size = %s\n", sign_size);
	
	/* Send Signature */
	
	printf("Server: Send Signature\n");
	
	printf("Creating socket...\n");
	int sockfd_1 = 0, sockfd_2 = 0;
	sockfd_1 = socket(AF_INET, SOCK_STREAM , 0);
	sockfd_2 = socket(AF_INET, SOCK_STREAM , 0);

	if (sockfd_1 == -1){
		printf("Fail to create socket 1.\n");
	} else printf("Socket 1 created.\n");
	
	if (sockfd_2 == -1){
		printf("Fail to create socket 2.\n");
	} else printf("Socket 2 created.\n");

	struct sockaddr_in client_info_1;
	bzero(&client_info_1, sizeof(client_info_1));
	client_info_1.sin_family = PF_INET;
	
	client_info_1.sin_addr.s_addr = inet_addr("127.0.0.1");
	client_info_1.sin_port = htons(8700);

	printf("Connecting to Client 1...\n");
	int err = connect(sockfd_1, (struct sockaddr*)&client_info_1, sizeof(client_info_1));
	if(err == -1){
		printf("Client 1 Connection Error.\n");
	}
	
	struct sockaddr_in client_info_2;
	bzero(&client_info_2, sizeof(client_info_2));
	client_info_2.sin_family = PF_INET;
	
	client_info_2.sin_addr.s_addr = inet_addr("127.0.0.2");
	client_info_2.sin_port = htons(8700);
	
	printf("Connecting to Client 2...\n");
	err = connect(sockfd_2, (struct sockaddr*)&client_info_2, sizeof(client_info_2));
	if(err == -1){
		printf("Client 2 Connection Error.\n");
	}
	
	int ret_1, ret_2, wait_1, wait_2, flag_1 = -1, flag_2 = -1;
	char receive_1[1024] = {}, receive_2[1024] = {};
	char success[] = {"Signature Received. Verification Approved.\n"};
	char fail[] = {"Verification failed.\n"};
	time_t start, end_1, end_2;
	start = time(NULL);
	
	printf("Sending Signature to Client 1 and 2...\n");
	send(sockfd_1, sign, sizeof(sign), 0);
	send(sockfd_2, sign, sizeof(sign), 0);
	printf("Sending Signature Size to Client 1 and 2...\n");
	send(sockfd_1, sign_size, sizeof(sign_size), 0);
	send(sockfd_2, sign_size, sizeof(sign_size), 0);
	printf("Sending Hash to Client 1 and 2...\n");
	send(sockfd_1, hash, sizeof(hash), 0);
	send(sockfd_2, hash, sizeof(hash), 0);
	printf("Sending Hash Size to Client 1 and 2...\n");
	send(sockfd_1, hash_size, sizeof(hash_size), 0);
	send(sockfd_2, hash_size, sizeof(hash_size), 0);
	printf("Receiving message from Client 1 and 2...\n");
	while(1){
recv_1:
		ret_1 = recv(sockfd_1, receive_1, sizeof(receive_1), MSG_DONTWAIT);
		if(ret_1 < 0){
			end_1 = time(NULL);
			wait_1 = difftime(end_1, start);
			if(wait_1 > 10){
				printf("Client 1 doesn't response.\n");
				flag_1 = 2;
				if(flag_2 == -1) goto recv_2;
				else break;
			} else if(flag_2 != -1) goto recv_1;
		}
		else{
			printf("From Client 1: %s\n", receive_1);
			if(strcmp(receive_1, success)) flag_1 = 0;
			else if(strcmp(receive_1, fail)) flag_1 = 1;
			else flag_1 = 2;
			if(flag_2 != -1) break;
		}
recv_2:
		ret_2 = recv(sockfd_2, receive_2, sizeof(receive_2), MSG_DONTWAIT);
		if(ret_2 < 0){
			end_2 = time(NULL);
			wait_2 = difftime(end_2, start);
			if(wait_2 > 10){
				printf("Client 2 doesn't response.\n");
				flag_2 = 2;
				if(flag_1 == -1) goto recv_1;
				else break;
			} else if(flag_1 != -1) goto recv_2;
		}
		else{
			printf("From Client 2: %s\n", receive_2);
			if(strcmp(receive_2, success) == 0) flag_2 = 0;
			else if(strcmp(receive_2, fail) == 0) flag_2 = 1;
			else flag_2 = 2;
			if(flag_1 != -1) break;
		}
	}
	
	if(flag_1 == 1) printf("Error: Signature failed at Client 1.\n");
	else if(flag_1 == 2) printf("Error: Client 1 may be attacked.\n");
	
	if(flag_2 == 1) printf("Error: Signature failed at Client 2.\n");
	else if(flag_2 == 2) printf("Error: Client 2 may be attacked.\n");
	
	memset(receive_1, 0, sizeof(receive_1));
	memset(receive_2, 0, sizeof(receive_2));
	
	/* Generate random AES Key and encrypt */
	
	printf("Prepare decode operation\n");
	prepare_aes(&ctx, DECODE);
	
	printf("Generate Random Key\n");
	gen_key(&ctx, AES_TEST_KEY_SIZE);
	
	printf("RSA Encrypt AES Key\n");
	rsa_encrypt(&ctx, rsa_ciph, &rsa_ciph_size);
	
	printf("Encrypted Key: %s\n", rsa_ciph);
	printf("size = %" PRIu32 "\n", rsa_ciph_size);
	char size[] = { rsa_ciph_size/100+'0', (rsa_ciph_size%100)/10+'0', (rsa_ciph_size%10)+'0' };
	
	/* Send encrypted AES Key */
	
	printf("Server: Send AES Key\n");
	
	char good[] = {"AES Key received.\n"};
	char bad[] = {"AES Key failed.\n"};
	
	ret_1 = 0, ret_2 = 0;
	flag_1 = -1, flag_2 = -1;
	
	if(flag_1 == 0){
		printf("Server: Send AES Key to Client 1\n");
send_1:
		printf("Sending Encrypted AES Key to Client 1...\n");
		send(sockfd_1, rsa_ciph, sizeof(rsa_ciph), 0);
		printf("Sending Encrypted AES Key Size to Client 1...\n");
		send(sockfd_1, size, sizeof(size), 0);
		printf("Sending Initial Vector to Client 1...\n");
		send(sockfd_1, iv, sizeof(iv), 0);
		start = time(NULL);
		printf("Receiving message from Client 1...\n");
		while(1){
			ret_1 = recv(sockfd_1, receive_1, sizeof(receive_1), MSG_DONTWAIT);
			if(ret_1 < 0){
				end_1 = time(NULL);
				wait_1 = difftime(end_1, start);
				if(wait_1 > 10){
					printf("Client 1 doesn't response.\n");
					flag_1 = 2;
					break;
				}
			}
			else{
				printf("From Client 1: %s\n", receive_1);
				if(strcmp(receive_1, good) == 0) flag_1 = 0;
				else if(strcmp(receive_1, bad) == 0) flag_1 = 1;
				else flag_1 = 2;
				break;
			}
		}
		if(flag_1 == 1){
			printf("Error: AES Key doesn't work at Client 1. Send again...\n");
			goto send_1;
		}
		if(flag_1 == 2) printf("Error: Client 1 may be attacked.\n");
		memset(receive_1, 0, sizeof(receive_1));
	}
	
	if(flag_2 == 0){
		printf("Server: Send AES Key to Client 2\n");
send_2:
		printf("Sending Encrypted AES Key to Client 2...\n");
		send(sockfd_2, rsa_ciph, sizeof(rsa_ciph), 0);
		printf("Sending Encrypted AES Key Size to Client 2...\n");
		send(sockfd_2, size, sizeof(size), 0);
		printf("Sending Initial Vector to Client 2...\n");
		send(sockfd_2, iv, sizeof(iv), 0);
		start = time(NULL);
		printf("Receiving message from Client 2...\n");
		while(1){
			ret_2 = recv(sockfd_2, receive_2, sizeof(receive_2), MSG_DONTWAIT);
			if(ret_2 < 0){
				end_2 = time(NULL);
				wait_2 = difftime(end_2, start);
				if(wait_2 > 10){
					printf("Client 2 doesn't response.\n");
					flag_2 = 2;
					break;
				}
			}
			else{
				printf("From Client 2: %s\n", receive_2);
				if(strcmp(receive_2, good) == 0) flag_2 = 0;
				else if(strcmp(receive_2, bad) == 0) flag_2 = 1;
				else flag_2 = 2;
				break;
			}
		}
		if(flag_2 == 1){
			printf("Error: AES Key doesn't work at Client 2. Send again...\n");
			goto send_2;
		}
		if(flag_2 == 2) printf("Error: Client 2 may be attacked.\n");
		memset(receive_2, 0, sizeof(receive_2));
	}
	
	/* Receive Client Status */
	
	printf("Server: Receive Client Status\n");
	
	int result, check_1 = -1, check_2 = -1;
	if(flag_1 == 0) check_1 = 0;
	if(flag_2 == 0) check_2 = 0;
	flag_1 = -1, flag_2 = -1;
	char receiveMessage[] = {"Data received.\n"};
	char failMessage[] = {"Incorrect Data.\n"};
	
	time_t start_1, start_2;
	start_1 = time(NULL);
	start_2 = time(NULL);
	printf("Client Linking...\n");
	while(1){
		if(check_1 == 0){
status_1:
			ret_1 = recv(sockfd_1, ciph, sizeof(ciph), MSG_DONTWAIT);
			if(ret_1 < 0){
				end_1 = time(NULL);
				wait_1 = difftime(end_1, start_1);
				if(wait_1 > 10){
					printf("Client 1 lost.\n");
					flag_1 = 2;
					if(check_2 == -1) break;
					else if(flag_2 == 2 || flag_2 == 0) break;
					else goto status_2;
				}
			}
			else{
				printf("From Client 1: %s\n", ciph);

				/* check message 1 correction */

				printf("Set key in TA\n");
				set_key(&ctx);

				printf("Reset ciphering operation in TA (provides the initial vector)\n");
				set_iv(&ctx, iv, AES_BLOCK_SIZE);

				printf("Decode buffer from TA\n");
				cipher_buffer(&ctx, ciph, AES_TEST_BUFFER_SIZE, &result);
				if(result == 0){
					printf("Incorrect Data. Request Client 1 to send again...\n");
					send(sockfd_1, failMessage, sizeof(failMessage), 0);
					flag_1 = 1;
					start_1 = time(NULL);
				}
				else{
					printf("Data 1 received.\n");
					send(sockfd_1, receiveMessage, sizeof(receiveMessage), 0);
					flag_1 = 0;
					check_1 = 1;
					if(check_2 == 1) break;
				}
				memset(ciph, 0, sizeof(ciph));
			}
		}

		if(check_2 == 0){
status_2:
			ret_2 = recv(sockfd_2, ciph, sizeof(ciph), MSG_DONTWAIT);
			if(ret_2 < 0){
				end_2 = time(NULL);
				wait_2 = difftime(end_2, start_2);
				if(wait_2 > 10){
					printf("Client 2 lost.\n");
					flag_2 = 2;
					if(check_1 == -1) break;
					else if(flag_1 == 2 || flag_1 == 0) break;
					else goto status_1;
				}
			}
			else{
				printf("From Client 2: %s\n", ciph);

				/* check message 2 correction */

				printf("Set key in TA\n");
				set_key(&ctx);

				printf("Reset ciphering operation in TA (provides the initial vector)\n");
				set_iv(&ctx, iv, AES_BLOCK_SIZE);

				printf("Decode buffer from TA\n");
				cipher_buffer(&ctx, ciph, AES_TEST_BUFFER_SIZE, &result);
				if(result == 0){
					printf("Incorrect Data. Request Client 2 to send again...\n");
					send(sockfd_2, failMessage, sizeof(failMessage), 0);
					flag_2 = 1;
					start_2 = time(NULL);
				}
				else{
					printf("Data 2 received.\n");
					send(sockfd_2, receiveMessage, sizeof(receiveMessage), 0);
					flag_2 = 0;
					check_2 = 1;
					if(check_1 == 1) break;
				}
				memset(ciph, 0, sizeof(ciph));
			}
		}
	}
	
	close(sockfd_1);
	close(sockfd_2);
	
	/* Encrypt Status */
	
	printf("Prepare encode operation\n");
	prepare_aes(&ctx, ENCODE);

	printf("Set key in TA\n");
	set_key(&ctx);

	printf("Reset ciphering operation in TA (provides the initial vector)\n");
	set_iv(&ctx, iv, AES_BLOCK_SIZE);

	printf("Encode buffer from TA\n");
	cipher_buffer(&ctx, ciph, AES_TEST_BUFFER_SIZE, &result);
	
	printf("ciph: %s\n", ciph);
	
	/* Send Status */
	
	printf("Client: Send Status\n");
	
	printf("Creating socket...\n");
	int sockfd = 0;
	sockfd = socket(AF_INET, SOCK_STREAM , 0);

	if (sockfd == -1){
		printf("Fail to create a socket.\n");
	} else printf("Socket created.\n");
	
	struct sockaddr_in info;
	bzero(&info, sizeof(info));
	info.sin_family = PF_INET;
	
	info.sin_addr.s_addr = inet_addr("127.0.0.1");
	info.sin_port = htons(8700);

	err = connect(sockfd, (struct sockaddr*)&info, sizeof(info));
	if(err == -1){
		printf("Connection error.\n");
	}
	
	char message[AES_TEST_BUFFER_SIZE] = {};
	char successMessage[] = {"Data Received.\n"};
	while(1){
		printf("Sending message to Server...\n");
		send(sockfd, ciph, sizeof(ciph), 0);
		printf("Receiving message from Server...\n");
		recv(sockfd, message, sizeof(message), 0);
		printf("From Server: %s\n", message);
		if(strcmp(message, successMessage) == 0) break;
		else printf("Prepare to send data again...\n");
	}
	
	close(sockfd);
	
	terminate_tee_session(&ctx);

	return 0;
}
