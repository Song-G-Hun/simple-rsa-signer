#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"

const char *PRIVATE_KEY_PEM = 
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIIEowIBAAKCAQEAt2T1nDAg8EIMpAZw+qP5mUntkLU75jAWpdyPjxyLo9vH+5xt\n"
"ZNffc5EMpIJugUX7ZLL9DrlRyWEI0c1SH+n64s2ZJ0dwN5+tx0fj5bsrJoobz0wA\n"
"JEhwfLSpCbdXZV2BQEnPB82e4gopgTjVBvGu0Vjvm5DOH43y4lE46DVG0qUODY5L\n"
"FS+acVM8iMjX+0WWXQ9r58hjD/jB812BtPaak7hkFiEvXRxsjZrRs8X/zzpmT7tD\n"
"/Gi8KJTS9eHwPAW3OvEu5AcHw3/EPqQvsFO4o5ZLhU/16Gixthuzueoj8jJcgJEk\n"
"Yt/E//nHwqGB2EHrrOtpNXCKmzx69hDSy9BpQwIDAQABAoIBABGzTNamToeMgxZ8\n"
"XgB9kw7tyQq5He7kSqCiM7jm/b3y7c+lvr6Hl1QwIRLqWSq2S8KMWUrygqeia0Ip\n"
"7viQPLFnO+uZRDDE2KDt71uyP5ft/IEldLNhH8+UIDyFKt+TBsaNrnhdAC4Q4ltL\n"
"1kO1T996FfuNyQHX/CPxHZehN2oHxQguCT6MqqcmrGv0U8VYbHX/GduwnvivYJ00\n"
"Wl9l1q0RvEdAfkbJwHZs+ja+ro9vK8GfHZ/T1KONp2uZKj9nlsxhn5INFNEfmCeO\n"
"dQClsyIGm/U46MzuEmJsZNKTlmyBO+dANaJ7QhApyQrgNIORVDIIBiqHJcElsX3t\n"
"9DjlpwECgYEA1A+ThM+QNREt3FWJoIwSGgRLwCXxMU41UGQU1WdSiaovMk18P1ok\n"
"sc7oOjjc+cd2MgIkRgLGbMlyUGE4zRhN9V34rkKpdzxciFatBaqKzDYT8WvI8xMb\n"
"pMloRfwuRGpOgivmm5Q+VWE4zUZ52dArQj++9wxdzXMhSSfMEriw6M8CgYEA3WTR\n"
"DrhurDx6D5TIE9vtsUtYZgg3P6Bfj0ULtkvn0EFDT9roDzsyJczU4uCl5RTPMQiC\n"
"TQUD6PmXfT3dWkQ8r8lrSJN4e+D4HrFNpODfb1pV99cQX2m+nb2x1x5PlUYtVXRW\n"
"enO4kGYnIqkcBmwB13uSpMhDucyNtHcWQU7yLU0CgYAYSZhps6Qej9Mi0yEqJCDG\n"
"ngtW/IF9VinBBVVlg6nuXnF9X2aFkvt06e+rC2wzp2agH6Kr6hFz0DapghkRVGFJ\n"
"YvPicXwbTeyDKPo0Fe5DqUXrdp7TSDL4UqEAsvtRlqNbQU/uLbJd8P6idBnsmmz5\n"
"73cdsGrl5vO+/zHeSwzn/QKBgH1BSp2/bq33UT97d2704JeL/ylKwKc4vpe6ApRS\n"
"gYZrRf/p45yqawbDyjXJz1G54jblj4KvsbSfcTukQpWNQaBanl3jQSkk8Hu86Ca+\n"
"Kus++qBLhrHUi8mGxxTjyzazC3braPnCessHYGDVuEtR1ADrot2jh92Ygxt0vJya\n"
"Y52JAoGBAI9pz3gOdP56qga0N1i3bOLc8QhztzOACQpaSrkONWHoYg70Tl0LOfdl\n"
"o0P7w5UAu//Tlfsy6IPC6lQrKvr74GZlZIVpIKReZs2TAdmUgw+ynJXT5/VTWA3t\n"
"merMHgSTXmOmaaSthY/bVISeoiOCBtsIgS5VN3/85NZ75cMBFnTN\n"
"-----END RSA PRIVATE KEY-----\n";


void show_menu() {
    dmsg("\n==== 메뉴 ====\n");
    dmsg("1. 개별키 출력\n");
    dmsg("2. 개별키 암호화 저장\n");
    dmsg("3. 개별키 복호화 후 출력\n");
    dmsg("4. readme.txt 파일 서명\n");
    dmsg("5. 서명 검증\n");
    dmsg("0. 종료\n");
    dmsg("선택하세요: ");
}

void print_hex(const char *label, const unsigned char *data, size_t len) {
    dmsg("%s:\n", label);
    for (size_t i = 0; i < len; ++i) {
        dmsg("%02X", data[i]);
        if ((i + 1) % 16 == 0) dmsg("\n");
    }
    if (len % 16 != 0) dmsg("\n");
}

int main(int argc, char *argv[]) {
    
    UCHAR randompool[512];
    UCHAR dk[32];

    int ret = 0;
    

    FILE *file;
    SECURE_KEY_CTX secure_ctx;
    
    unsigned char iv[16] = "0123456789abcdef";
    unsigned char ciphertext[2048], plaintext[2048] = {0};
    int  ciphertext_len;
    char verData[16] = "KOR1.00";
    //char file_path[256] = "readme.txt";
   // char secure_path[256] = "secure.bin";
    char tmp[256];
    
    if (argc < 4) {
        dmsg("사용법: %s -s <보안파일경로> -v <버전> -t <파일경로> -c <실행모드>\n", argv[0]);       
        dmsg("\t실행모드 : 1. 미지원 \n");
        dmsg("\t실행모드 : 2. 개별키 암호화 저장\n");
        dmsg("\t실행모드 : 3. 개별키 복호화 후 출력\n");
        dmsg("\t실행모드 : 4. 대상 파일 서명\n");
        dmsg("\t실행모드 : 5. 서명 검증\n");
        dmsg("\t실행모드 : 0. 종료\n");
        return 1;
    }

   int opt;
    char *secure_path = NULL;
    char *version = NULL;
    char *file_path = NULL;
    int choice = 0;
    
    while ((opt = getopt(argc, argv, "s:v:t:c:")) != -1) {
        switch (opt) {
            case 's':
                secure_path = optarg;
                break;
            case 'v':
                version = optarg;
                convert_to_uppercase(version,verData);
                break;
            case 't':
                file_path = optarg;                
                break;
            case 'c':
                choice = atoi(optarg);
                break;
            default:
                dmsg("❌ 사용법: %s -s <보안파일경로> -v <버전> -t <파일경로> -c <실행모드>\n", argv[0]);
                dmsg("예시: %s -s secure.bin -v KOR1.00 -t readme.txt -c 1\n", argv[0]);
                return 1;
        }
    }



    initialize_rng();
    //while (running) {
    do{        
        switch (choice) {
            case 1:
               // dmsg("📄 개별키 출력\n%s\n", PRIVATE_KEY_PEM);
                break;

            case 2: //api_SavePemKey();
                if(secure_path == NULL) {
                    dmsg("❌ 보안파일 경로를 입력해주세요.\n");
                    break;
                }
                if(version == NULL) {
                    dmsg("❌ 버전을 입력해주세요.\n");
                    break;
                }
                
                if(file_path == NULL) {
                    dmsg("❌ 파일 경로를 입력해주세요.\n");
                    break;
                }
                dmsg("🔒 보안파일 경로 : %s\n", secure_path);
                dmsg("🔒 버전 : %s\n", verData);
                dmsg("🔒 파일 경로 : %s\n", file_path);

                generate_random_bytes(randompool, sizeof(randompool));
                derive_key(randompool, sizeof(randompool), dk, sizeof(dk));
                
                generate_random_bytes((uint8_t*)&secure_ctx, sizeof(SECURE_KEY_CTX));
                memcpy(secure_ctx.random, randompool, sizeof(randompool));

                secure_ctx.encrypted_key_len=api_Aes128Encrypt(dk, iv, (const unsigned char *)PRIVATE_KEY_PEM, strlen(PRIVATE_KEY_PEM), ciphertext);
                memcpy(secure_ctx.encrypted_key, ciphertext, secure_ctx.encrypted_key_len);
                compute_sha256((const UCHAR*)ciphertext, secure_ctx.encrypted_key_len, secure_ctx.key_hash);

                secure_ctx.iversion_len=api_Aes128Encrypt(dk, iv, (const unsigned char *)verData, strlen(verData), ciphertext);
                memcpy(secure_ctx.caVersion, ciphertext, secure_ctx.iversion_len);
                compute_sha256((const UCHAR*)secure_ctx.caVersion, secure_ctx.iversion_len, secure_ctx.ver_hash);

                //dmsg("🔒 암호화된 PEM (%d bytes):\n", ciphertext_len);

                file = fopen(secure_path, "wb");
                if (file) {
                    fwrite(&secure_ctx, sizeof(SECURE_KEY_CTX), 1, file);
                    fclose(file);
                    dmsg("✅ 보안파일 %s에 저장되었습니다.\n", secure_path);
                } else {
                    dmsg("❌ 파일 저장 실패\n");
                }
                break;

            case 3://api_loadPemKey();
                ret = api_LoadSecureFile(secure_path, plaintext, tmp);
                if (ret < 0) {
                    dmsg("❌ %s 로딩 실패: %d\n", secure_path, ret);
                    
                }else{
                    dmsg("✅ %s 로딩 성공\n", secure_path);
                    //dmsg("🔓 복호화된 PEM:\n%s\n", plaintext);
                    dmsg("🔓 복호화된 버전 정보: %s\n", tmp);
                }
                break;

            case 4: //api_SigninatureFwFile(); //pc용
                
                if(version == NULL) {
                    dmsg("❌ 버전을 입력해주세요.\n");
                    break;
                }
                
                if(file_path == NULL) {
                    dmsg("❌ 파일 경로를 입력해주세요.\n");
                    break;
                }
                ret = api_MakeSignatureFwFile(file_path, "private.pem", verData);
                dmsg("함수 결과 : %d\n", ret);
               
                break;

            case 5: //api_VerifySignatureFwFile();
            case 6:            
                if(version != NULL) {
                    dmsg(" ❌ 입력된 버전은 사용되지 않습니다\n");
                }
                if(file_path == NULL) {
                    dmsg("❌ 파일 경로를 입력해주세요.\n");
                    break;
                }
                ret =  api_VerifySignatureFwFile(file_path, secure_path,tmp); //tmp에는 버전이 저장됨.
                if (ret < 0) {
                    dmsg("❌ 서명 검증 실패: %d\n", ret);
                    break;
                }
                if(choice == 5)
                    dmsg("✅ 서명 검증 성공!\n");
                else{
                    dmsg("✅ 서명 검증 성공! 저장!\n");
                    api_SaveSecureFile(secure_path, tmp);
                }                
                break;
                           
            default:
                dmsg("❌ 잘못된 메뉴입니다. 다시 선택해주세요.\n");
                ret = -100;
                break;
        }
    }while(0);
    return ret;
}