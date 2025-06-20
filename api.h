#ifndef __SECURE_API_H_
#define __SECURE_API_H_

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

typedef char                       CHAR;
typedef unsigned char              UCHAR;
typedef int                        INT;
typedef unsigned int               UINT;
typedef unsigned long              ULONG;

#define _DEBUG 
#ifdef  _DEBUG
#define dmsg(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define dmsg(fmt, ...) //do {} while (0)
#endif

#define SEC_BLOCK_SIZE 1024

typedef struct __attribute__((packed)) {
    unsigned char random[512];
    unsigned char encrypted_key[2048];
    int encrypted_key_len;
    unsigned char key_hash[32];
    char caVersion[32];
    int iversion_len;    
    unsigned char ver_hash[32];
} SECURE_KEY_CTX;

typedef struct __attribute__((packed)) {
    unsigned char signature[512];
    int signature_len;
    unsigned char random[512];
    unsigned char encrypted_version[128];
    int encrypted_version_len;
} SIGNATURE_CTX;

void clear_memory(char *dest, unsigned char value, int length);
unsigned int crc32_init(unsigned int seed);
unsigned int crc32_fast(unsigned int sum, unsigned char *data, unsigned int length);
void derive_key(UCHAR *random_pool, int pool_size, UCHAR *dk, int dk_size);
void compute_sha256(const UCHAR *input, size_t input_len, UCHAR *output);
void generate_random_bytes(uint8_t *buffer, size_t size);
uint32_t well512_random();
int initialize_rng();
int get_file_hash(const char *filepath, unsigned char *hash);

int api_Aes128Encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext);
int api_Aes128Decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext);

int api_MakeSignatureFwFile(const char *filepath, const char *pem_filePath, const char *version);
int api_LoadSecureFile(const char *filepath, unsigned char *PrivateKey,char *caVersion);
int api_VerifySignatureFwFile(const char *filepath, const char *secFilePath, char *version);
int api_SaveSecureFile(const char *filepath,char *caVersion);

void convert_to_uppercase(const char *str,char *dest);
char* get_base_filename(const char *filepath);
char* get_signature_filename(const char *filepath);
#endif