#include "api.h"

void clear_memory(char *dest, unsigned char value, int length) {
    for (int i = 0; i < length; i++)
        dest[i] = value;
}

static const unsigned int crc32_table[256] = {
0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9,
  0x130476dc, 0x17c56b6b, 0x1a864db2, 0x1e475005, 
  0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61, 
  0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd, 
  0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9, 
  0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
  0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011, 
  0x791d4014, 0x7ddc5da3, 0x709f7b7a, 0x745e66cd, 
  0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039, 
  0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5, 
  0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81,
  0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d, 
  0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49, 
  0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95, 
  0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1, 
  0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d,
  0x34867077, 0x30476dc0, 0x3d044b19, 0x39c556ae, 
  0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072, 
  0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16, 
  0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca, 
  0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde,
  0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02, 
  0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1, 0x53dc6066, 
  0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba, 
  0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e, 
  0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692,
  0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6, 
  0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a, 
  0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e, 
  0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2, 
  0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686,
  0xd5b88683, 0xd1799b34, 0xdc3abded, 0xd8fba05a, 
  0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637, 
  0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb, 
  0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f, 
  0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
  0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47, 
  0x36194d42, 0x32d850f5, 0x3f9b762c, 0x3b5a6b9b, 
  0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff, 
  0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623, 
  0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7,
  0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b, 
  0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f, 
  0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3, 
  0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7, 
  0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b,
  0x9b3660c6, 0x9ff77d71, 0x92b45ba8, 0x9675461f, 
  0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3, 
  0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640, 
  0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c, 
  0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8,
  0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24, 
  0x119b4be9, 0x155a565e, 0x18197087, 0x1cd86d30, 
  0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec, 
  0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088, 
  0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654,
  0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0, 
  0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c, 
  0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18, 
  0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4, 
  0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0,
  0x9abc8bd5, 0x9e7d9662, 0x933eb0bb, 0x97ffad0c, 
  0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668, 
  0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4 

};

unsigned int crc32_init(unsigned int seed) {
    unsigned int init = 0;
    for (int val = 24; val >= 0; val -= 8) {
        unsigned int byte = (seed >> val) & 0xFF;
        init = crc32_table[((init >> 24) ^ byte) & 0xFF] ^ (init << 8);
    }
    return init;
}

unsigned int crc32_fast(unsigned int sum, unsigned char *data, unsigned int length) {
    while (length--)
        sum = crc32_table[(sum >> 24) ^ *data++] ^ (sum << 8);
    return sum;
}

int get_file_hash(const char *filepath, unsigned char *hash) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) return -1;

    unsigned char buffer[SEC_BLOCK_SIZE];
    int read_size = 0, total_size = 0;
    unsigned long crc = crc32_init(0xFFFFFFFF);

     do{		
        read_size = fread(buffer, 1, SEC_BLOCK_SIZE, fp);       
        if(read_size <= 0){           
            break;
        } 			
        total_size += read_size;		
        crc = crc32_fast(crc, buffer ,read_size);
    }while(1);

    // while ((read_size = fread(buffer, 1, SEC_BLOCK_SIZE, fp)) > 0) {
    //     total_size += read_size;
    //     crc = crc32_fast(crc, buffer, read_size);
    // }
    fclose(fp);

    buffer[0] = (crc >> 24) & 0xFF;
    buffer[1] = (crc >> 16) & 0xFF;
    buffer[2] = (crc >> 8) & 0xFF;
    buffer[3] = crc & 0xFF;
    buffer[4] = (total_size >> 24) & 0xFF;
    buffer[5] = (total_size >> 16) & 0xFF;
    buffer[6] = (total_size >> 8) & 0xFF;
    buffer[7] = total_size & 0xFF;

    compute_sha256(buffer, 8, hash);
    clear_memory((char *)buffer, 0, sizeof(buffer));
    return 32;
}
static uint32_t w512_state[16];
static uint32_t well_index = 0;
int initialize_rng() {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;

    ssize_t read_bytes = read(fd, w512_state, sizeof(w512_state));
    if (read_bytes != sizeof(w512_state)) {
        perror("Failed to read enough random data");         
    }
    close(fd);    

    uint32_t t = (uint32_t)time(NULL);
    for (int i = 0; i < 16; i++)
        w512_state[i] ^= (t + i * 2654435761u);

    well_index = 0;
    return 0;
}

uint32_t well512_random() {
    uint32_t a, b, c, d;
    a = w512_state[well_index];
    c = w512_state[(well_index + 13) & 15];
    b = a ^ c ^ (a << 16) ^ (c << 15);
    c = w512_state[(well_index + 9) & 15];
    c ^= (c >> 11);
    a = w512_state[well_index] = b ^ c;
    d = a ^ ((a << 5) & 0xDA442D24U);
    well_index = (well_index + 15) & 15;
    w512_state[well_index] ^= d;
    return w512_state[well_index];
}

void generate_random_bytes(uint8_t *buffer, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        uint32_t r = well512_random();
        for (int i = 0; i < 4 && offset < size; i++) {
            buffer[offset++] = (r >> (8 * i)) & 0xFF;
        }
    }
}

void compute_sha256(const UCHAR *input, size_t input_len, UCHAR *output) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input, input_len);
    SHA256_Final(output, &sha256);
}

void derive_key(UCHAR *random_pool, int pool_size, UCHAR *dk, int dk_size) {
    if (dk_size > 32) dk_size = 32;
    UCHAR idx[33] = {0};
    UCHAR temp[33] = {0};

    compute_sha256(random_pool + (pool_size >> 1), pool_size >> 1, idx);

    for (int i = 0; i < dk_size; i++) {
        temp[i] = random_pool[(random_pool[idx[i % 16]] + (i / 16)) % pool_size];
    }

    compute_sha256(temp, dk_size, idx);
    memcpy(dk, idx, dk_size);
    clear_memory((char *)idx, 0, sizeof(idx));
    clear_memory((char *)temp, 0, sizeof(temp));
}

int api_Aes128Encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int api_Aes128Decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    int plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

//filepath : fw파일의 경로
//pem_filePath : 서명할 pem파일경로
// version : fw버전정보
// return : 0 성공, 0 <  실패
// 서명파일은 filepath의 펌웨어 파일명과 동일하게 하고, 확장자는 sig로 한다.
int api_MakeSignatureFwFile(const char *filepath, const char *pem_filePath, const char *version)
{
    if(filepath == NULL || pem_filePath == NULL || version == NULL) return -1;

    dmsg("입력 정보 \n");
    dmsg("파일 경로 : %s\n", filepath);
    dmsg("pem 파일 경로 : %s\n", pem_filePath);
    dmsg("버전 정보 : %s\n", version);

    unsigned char hash[SHA256_DIGEST_LENGTH]={0,};
    if (get_file_hash(filepath, hash) < 0) {
        dmsg("❌ %s 해시 실패\n", filepath);
        return -2;
    }    
    
    FILE *pem_file = fopen(pem_filePath, "r");
    if (!pem_file) {        
        return -3;
    }

    RSA *rsa = PEM_read_RSAPrivateKey(pem_file, NULL, NULL, NULL);
    fclose(pem_file);
    if (!rsa) {        
        return -4;
    }

    unsigned char signature[256];
    unsigned int sig_len;
    
    if (RSA_sign(NID_sha256, hash, 32, signature, &sig_len, rsa) != 1) {
        RSA_free(rsa);        
        return -5;
    }
    
    RSA_free(rsa);
    
    // Save the signature and version information
    SIGNATURE_CTX sign_ctx;
    generate_random_bytes((uint8_t*)&sign_ctx, sizeof(SIGNATURE_CTX));
    
    memcpy(sign_ctx.signature, signature, sig_len);
    sign_ctx.signature_len = sig_len;
    
    //generate_random_bytes(sign_ctx.random, sizeof(sign_ctx.random));    
    unsigned char dk[32]= {0,};
    unsigned char iv[16] = "0123456789abcdef";
    unsigned char ciphertext[128];
    int ciphertext_len;
    derive_key(sign_ctx.random, sizeof(sign_ctx.random), dk, sizeof(dk));    

    ciphertext_len = api_Aes128Encrypt(dk, iv, (const unsigned char *)version, strlen(version), ciphertext);
    if (ciphertext_len < 0) {
        dmsg("❌ 암호화 실패\n");
        return -6;
    }
    memcpy(sign_ctx.encrypted_version, ciphertext, ciphertext_len);
    sign_ctx.encrypted_version_len = ciphertext_len;
    
    char *sigFileName = get_signature_filename(filepath);
    //filepath문자열에서 마지막 .을 찾고 확장자를 제거한 후 .sig 확장자를 추가
    
    dmsg("서명파일명 : %s\n", sigFileName);
    
    FILE *sig_file = fopen(sigFileName, "wb");
    if (!sig_file) {    
        return -7;
    }
    
    fwrite(&sign_ctx, sizeof(SIGNATURE_CTX), 1, sig_file);
    fclose(sig_file);
    dmsg("✅ 서명 정보가 %s에 저장되었습니다.\n", sigFileName);    

    clear_memory((char *)dk, 0, sizeof(dk));
    return 0; // Success
}

int api_LoadSecureFile(const char *filepath, unsigned char *PrivateKey,char *caVersion)
{
    if(filepath == NULL || (PrivateKey == NULL && caVersion == NULL)) return -1;

    //dmsg("파일 경로 : %s\n", filepath);  

    FILE *file = fopen(filepath, "rb");
    if (!file) {
        return -2;
    }

    SECURE_KEY_CTX secure_key_ctx;
    size_t readCnt = fread(&secure_key_ctx, sizeof(SECURE_KEY_CTX), 1, file);
    fclose(file);
    if (readCnt != 1) {
        dmsg("❌ 파일 읽기 실패: %s / %zu \n", filepath, readCnt);
        return -1000; // File read error
    }

    // Verify the key hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    compute_sha256((const UCHAR*)secure_key_ctx.encrypted_key, secure_key_ctx.encrypted_key_len, hash);
    if (memcmp(hash, secure_key_ctx.key_hash, 32) != 0) {
        dmsg("❌ 해시 검증 실패: 키 데이터 변조 가능성 있음\n");
        return -3; // Hash verification failed
    }
    compute_sha256((const UCHAR*)secure_key_ctx.caVersion, secure_key_ctx.iversion_len, hash);
    if (memcmp(hash, secure_key_ctx.ver_hash, 32) != 0) {
        dmsg("❌ 해시 검증 실패: 버전정보 변조 가능성 있음\n");
        return -4; // Hash verification failed
    }

    // Decrypt the key
    unsigned char dk[32] = {0};
    unsigned char iv[16] = "0123456789abcdef"; // Initialization vector
    derive_key(secure_key_ctx.random, sizeof(secure_key_ctx.random), dk, sizeof(dk));

    int plaintext_len;    
    unsigned char plaintext[2048] = {0}; // Buffer for decrypted data
    plaintext_len=api_Aes128Decrypt(dk, iv, (const unsigned char *)secure_key_ctx.encrypted_key, secure_key_ctx.encrypted_key_len, plaintext);
    //dmsg("🔓 복호화된 PEM (%d bytes):\n%s\n", plaintext_len, plaintext);
    if (PrivateKey!=NULL && plaintext_len > 0) {
        memcpy(PrivateKey, plaintext, plaintext_len);
        PrivateKey[plaintext_len] = '\0'; // Null-terminate the string
    }

    plaintext_len=api_Aes128Decrypt(dk, iv, (const unsigned char *)secure_key_ctx.caVersion, secure_key_ctx.iversion_len, plaintext);
    //  dmsg("🔓 복호화된 버전 정보 (%d bytes): %.*s\n", plaintext_len, plaintext_len, plaintext);
    if (caVersion != NULL && plaintext_len > 0) {
        memcpy(caVersion, plaintext, plaintext_len);
        caVersion[plaintext_len] = '\0'; // Null-terminate the string
    }    
    clear_memory((char *)plaintext, 0, sizeof(plaintext));
    clear_memory((char *)dk, 0, sizeof(dk));
    clear_memory((char *)&secure_key_ctx, 0,sizeof(SECURE_KEY_CTX));
    return 0; // Success
}
int compareVersion(char *oldVer, char *newVer) {
    if (strlen(oldVer) <= 3 || strlen(newVer) <= 3) {
        // 입력이 잘못된 경우 처리
        return 0;
    }

    //앞 3자리가 다르면 업데이트 해야함.
    if(memcmp(oldVer, newVer, 3) != 0) {
        return 1;
    }
    // 앞 3글자 제외한 문자열을 숫자 문자열로 취급
    double oldVersionNum = atof(oldVer + 3);
    double newVersionNum = atof(newVer + 3);

    if (oldVersionNum > newVersionNum) {
        return -1;
    } else if (oldVersionNum < newVersionNum) {
        return 1;
    } else {
        return 0;
    }
}

int api_VerifySignatureFwFile(const char *filepath, const char *secFilePath, char *version)
{
    if(filepath == NULL || secFilePath == NULL ) return -1;
    if (strlen(filepath) < 4 || strlen(secFilePath) < 4) return -1;
    //확장자포함해서 4자리 미만이 올수가 없음.

    dmsg("입력 정보 \n");
    dmsg("파일 경로 : %s\n", filepath);
    dmsg("서명 파일 경로 : %s\n", secFilePath);
    
    //filepath의 파일이 존재하는지 검사
    if (access(filepath, F_OK) != 0) {
        dmsg("❌ %s 파일이 존재하지 않습니다.\n", filepath);
        return -2; // File does not exist
    }
    char *sigFileName = get_signature_filename(filepath);
    
    dmsg("서명파일명 : %s\n", sigFileName);
    //서명파일이 존재하는지 검사
    if (access(sigFileName, F_OK) != 0) {
        dmsg("❌ %s 서명 파일이 존재하지 않습니다.\n", sigFileName);
        return -3; // Signature file does not exist
    }
    unsigned char hash[SHA256_DIGEST_LENGTH] = {0};
    unsigned char caPem[2048] = {0};
    char savedVersion[256] = {0};
    char newVersion[256] = {0};
    int ret;

    ret = api_LoadSecureFile(secFilePath, caPem, savedVersion);
    if (ret < 0) {
        dmsg("❌ 암호화 파일 로드 실패: %d\n", ret-1000);
        return ret; // Failed to load signature file
    }

    //dmsg("🔓 복호화된 CA PEM (%d bytes):\n%s\n", strlen(caPem), caPem);
    //dmsg("🔓 복호화된 버전 정보 (%d bytes): %s\n", strlen(savedVersion), savedVersion);

    //////////////////////////////////////////////////////
    // sig파일을 불러오기
    SIGNATURE_CTX secure_sign_ctx;
    unsigned char dk[32] = {0};
    unsigned char iv[16] = "0123456789abcdef"; // Initialization vector
    int plaintext_len;
    //unsigned char plaintext[2048] = {0}; // Buffer for decrypted data
    unsigned char signature[256];
    unsigned int sig_len;

    FILE *file = fopen(sigFileName, "rb");
    if (!file) {
        dmsg("❌ %s 서명 파일 열기 실패\n", sigFileName);
        ret = -4;
        goto END; // Failed to open signature file
    }
    size_t readCnt = fread(&secure_sign_ctx, sizeof(SIGNATURE_CTX), 1, file);
    fclose(file);

    if(readCnt != 1) {
        dmsg("❌ %s 서명 파일 읽기 실패\n", sigFileName);
        ret = -5;
        goto END; // Failed to read signature file
    }

    derive_key(secure_sign_ctx.random, sizeof(secure_sign_ctx.random), dk, sizeof(dk));
    plaintext_len = api_Aes128Decrypt(dk, iv, secure_sign_ctx.encrypted_version, secure_sign_ctx.encrypted_version_len, (unsigned char *)newVersion);
    if (plaintext_len < 0) {
        dmsg("❌ 복호화 실패\n");
        ret = -5;
        goto END; // Decryption failed
    }
    dmsg("🔓 신규 버전 정보 (%d bytes): %s\n", plaintext_len, newVersion);    
    dmsg("✅ 이전 버전 정보 (%d bytes): %s\n", strlen(savedVersion), savedVersion);
    if(compareVersion(savedVersion, newVersion) <0) {        
        dmsg("❌ 신규 버전이 이전 버전보다 낮습니다.\n");
        ret = -6; // Version mismatch
        goto END;
    }
    
    ///서명 데이터 생성
    if (get_file_hash(filepath, hash) < 0) {
        dmsg("❌ %s 해시 실패\n", filepath);
        ret = -7 - 2000; // Hash failure
        goto END;
    }    
    BIO *bio = NULL;    
    bio = BIO_new_mem_buf(caPem, -1);
    if (!bio) {
        dmsg("❌ BIO_new_mem_buf 실패\n");
        ret = -8 - 2000;
        goto END;
    }
    RSA *rsa = NULL;
    rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!rsa) {
        dmsg("❌ RSA 키 로딩 실패\n");
        ret = -9 - 2000;
        goto END;
    }    
    
    if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, &sig_len, rsa) != 1) {
        dmsg("❌ 서명 재생성 실패\n");
        RSA_free(rsa);
        ret = -10 - 2000; // Signature generation failed
        goto END;
    }
    RSA_free(rsa);

    if (sig_len != secure_sign_ctx.signature_len) {
        dmsg("❌ 서명 길이가 일치하지 않습니다.\n");
        ret = -11 - 2000; // Signature length mismatch
        goto END;
    }
    if (memcmp(signature, secure_sign_ctx.signature, sig_len) != 0) {
        dmsg("❌ 서명 불일치\n");
        ret = -12 - 2000; // Signature mismatch
    } else {
        dmsg("✅ 서명 일치 확인됨\n");
        ret = 0; // Success
        memcpy(version, newVersion, plaintext_len); // Copy new version to output
        
    }

/////////////////////////////////////
    

END:
    clear_memory((char *)dk, 0, sizeof(dk));
    clear_memory((char *)&caPem, 0, sizeof(caPem));
    clear_memory((char *)&savedVersion, 0, sizeof(savedVersion));
    clear_memory((char *)&secure_sign_ctx, 0, sizeof(SIGNATURE_CTX));
    clear_memory((char *)hash, 0, sizeof(hash));
    clear_memory((char *)signature, 0, sizeof(signature));

    return ret;
}

//caVersion, 널이면 단순 보안파일 갱신
int api_SaveSecureFile(const char *filepath,char *caVersion)
{
    if(filepath == NULL ) return -1;
    if(strlen(filepath) < 4 ) return -1; 

    int ret = 0;
    SECURE_KEY_CTX secure_ctx;    
    unsigned char dk[32] = {0,};
    unsigned char iv[16] = "0123456789abcdef"; // Initialization vector
    unsigned char ciphertext[2048] = {0}; // Buffer for encrypted data
    unsigned char caPem[2048] = {0}; // Buffer for CA PEM
    char caOldVer[256] = {0}; // Buffer for CA version

    //dmsg("파일 경로 : %s\n", filepath);  

    ret = api_LoadSecureFile(filepath, caPem, caOldVer);
    if (ret < 0) {
        dmsg("❌ 암호화 파일 로드 실패: %d\n", ret-1000);
        goto END; // Failed to load secure file
    }

    generate_random_bytes((uint8_t*)&secure_ctx, sizeof(SECURE_KEY_CTX));
    derive_key(secure_ctx.random, sizeof(secure_ctx.random), dk, sizeof(dk));

    secure_ctx.encrypted_key_len=api_Aes128Encrypt(dk, iv, (const unsigned char *)caPem, (int)strlen((const char *)caPem), ciphertext);
    memcpy(secure_ctx.encrypted_key, ciphertext, secure_ctx.encrypted_key_len);
    compute_sha256((const UCHAR*)ciphertext, secure_ctx.encrypted_key_len, secure_ctx.key_hash);

    if(caVersion!=NULL && strlen(caVersion) >= 6) {//신규버전이 있으면 ? 
        memset(caOldVer, 0, sizeof(caOldVer));
        strncpy(caOldVer, caVersion, sizeof(caOldVer) - 1);
    }
    secure_ctx.iversion_len=api_Aes128Encrypt(dk, iv, (const unsigned char *)caOldVer, (int)strlen((const char *)caOldVer), ciphertext);
    memcpy(secure_ctx.caVersion, ciphertext, secure_ctx.iversion_len);
    compute_sha256((const UCHAR*)secure_ctx.caVersion, secure_ctx.iversion_len, secure_ctx.ver_hash);

    FILE *file = fopen(filepath, "wb");    
    if (file) {
        fwrite(&secure_ctx, sizeof(SECURE_KEY_CTX), 1, file);
        fclose(file);
        dmsg("✅ %s에 저장되었습니다.\n", filepath);
        ret = 0; // Success
    } else {
        dmsg("❌ 파일 저장 실패\n");
        ret = -2; // File save failure
    }

END:    
    clear_memory((char *)dk, 0, sizeof(dk));
    clear_memory((char *)&secure_ctx, 0, sizeof(SECURE_KEY_CTX));
    clear_memory((char *)caPem, 0, sizeof(caPem));
    clear_memory((char *)ciphertext, 0, sizeof(ciphertext));
    
    return ret;
}

void convert_to_uppercase(const char *str,char *dest) {
    if (str == NULL || dest == NULL) return;
    int i;
    for (i = 0; str[i] != '\0'; i++) {      
        if (!isspace(str[i])) {   
            dest[i] = toupper(str[i]);
        }
    }
    dest[i] = '\0';
}
char* get_basename(const char *path) {
    if (path == NULL) return NULL;
    
    // 마지막 슬래시('/') 찾기
    const char *last_slash = strrchr(path, '/');
    
    // 슬래시가 없으면 전체 경로를 반환
    if (last_slash == NULL) {
        return strdup(path);
    }
    
    // 슬래시 다음 문자부터 끝까지 복사
    return strdup(last_slash + 1);
}
char* get_base_filename(const char *filepath) {
    if (filepath == NULL) return NULL;
    
    // 파일 경로에서 파일명만 추출
    char *path_copy = strdup(filepath);
    if (path_copy == NULL) return NULL;
    
    char *filename = get_basename(path_copy);
    char *result = strdup(filename);
    free(path_copy);
    
    return result;
}
char* get_dirname(const char* path) {
    if (path == NULL) return NULL;

    const char* last_slash = strrchr(path, '/');
    if (last_slash == NULL) {
        // 슬래시 없음 → 현재 디렉토리
        return strdup(".");
    }

    size_t len = last_slash - path;
    if (len == 0) len = 1;  // root "/"
    
    char* dir = malloc(len + 1);
    if (dir == NULL) return NULL;

    strncpy(dir, path, len);
    dir[len] = '\0';
    return dir;
}
char* get_signature_filename(const char *filepath) {
    if (filepath == NULL) return NULL;

    // 원본 경로 복사 (dirname, basename은 원본을 수정)
    char *path_copy1 = strdup(filepath);
    char *path_copy2 = strdup(filepath);
    if (!path_copy1 || !path_copy2) {
        free(path_copy1); free(path_copy2);
        return NULL;
    }

    char *dir = get_dirname(path_copy1);    // 디렉토리 경로
    char *file = get_base_filename(path_copy2);  // 파일 이름

    // 확장자 제거
    char *dot = strrchr(file, '.');
    if (dot != NULL) {
        *dot = '\0';
    }

    // 결과 경로 버퍼 할당: dir + "/" + file + ".sig" + '\0'
    size_t total_len = strlen(dir) + 1 + strlen(file) + 4 + 1;
    char *sig_path = malloc(total_len);
    if (sig_path == NULL) {
        free(path_copy1); free(path_copy2);
        return NULL;
    }

    snprintf(sig_path, total_len, "%s/%s.sig", dir, file);

    free(path_copy1);
    free(path_copy2);
    return sig_path;
}