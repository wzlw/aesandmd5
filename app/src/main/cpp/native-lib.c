#include <string.h>
#include <jni.h>
#include <android/log.h>
#include "openssl/md5.h"
#include "openssl/evp.h"
#include "openssl/bio.h"
#include "openssl/buffer.h"

#define LOG_TAG "jni-log"
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,LOG_TAG,__VA_ARGS__)


const unsigned char *_key = (const unsigned char *) "0123456789012345";

// base64 编码
char * base64Encode(const char *buffer, int length)
{
    BIO *bmem = NULL;
    BIO *b64 = NULL;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, buffer, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    BIO_set_close(b64, BIO_NOCLOSE);

    char *buff = (char *)malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;
    BIO_free_all(b64);

    return buff;
}

// base64 解码
char * base64Decode(char *input, int length)
{
    BIO *b64 = NULL;
    BIO *bmem = NULL;
    char *buffer = (char *)malloc(length);
    memset(buffer, 0, length);
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf(input, length);
    bmem = BIO_push(b64, bmem);
    BIO_read(bmem, buffer, length);
    BIO_free_all(bmem);

    return buffer;
}

char *encrypt(char *content) {
    // 待加密的数据
    const unsigned char *vItem = content;
    // 源数据长度
    int inLen = (int) strlen((const char *) vItem);
    // 加密长度
    int encLen = 0;
    // 输出长度
    int outlen = 0;
    // 加密数据长度
    unsigned char encData[1024] = {0};

    LOGW("source: %s\n", vItem);
    // 创建加密上下文
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    // 初始化加密上下文
    EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), NULL, _key, NULL, 1);
    // 加密数据
    EVP_CipherUpdate(ctx, encData, &outlen, vItem, inLen);
    // 拼接长度
    encLen = outlen;
    // 结束加密
    EVP_CipherFinal(ctx, encData + outlen, &outlen);
    // 拼接
    encLen += outlen;
    // 释放
    EVP_CIPHER_CTX_free(ctx);
    // base64编码
    char *baseEnc = base64Encode(encData, encLen);
    LOGW("encrypted : %s\n", baseEnc);
    return baseEnc;
}

char * decrypt(char *baseEnc) {
    // base64解码
    char *encData1 = base64Decode(baseEnc, (int) strlen(baseEnc));
    // 解密长度
    int decLen = 0;
    // 解码数据长度
    int outlen = 0;
    // 解码后的数据
    unsigned char decData[1024];
    // 创建解密上下文
    EVP_CIPHER_CTX *ctx2 = EVP_CIPHER_CTX_new();
    // 初始化解密
    EVP_CipherInit_ex(ctx2, EVP_aes_128_ecb(), NULL, _key, NULL, 0);
    // 执行解密
    EVP_CipherUpdate(ctx2, decData, &outlen, (const unsigned char *) encData1, strlen(encData1));
    // 设置长度
    decLen = outlen;
    // 结束解密
    EVP_CipherFinal(ctx2, decData + outlen, &outlen);
    // 拼接长度
    decLen += outlen;
    // 释放
    EVP_CIPHER_CTX_free(ctx2);
    // 设置字符串结尾标识
    decData[decLen] = '\0';
    LOGW("decrypt %s", decData);
    return decData;
}

char * md5(char *content) {
    char result[MD5_DIGEST_LENGTH] = {0};
    MD5(content, strlen(content), &result);
    char tmp[3]={0}, buf[33]={'\0'};
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        sprintf(tmp, "%02X", result[i]);
        strcat(buf, tmp);
    }
    return buf;
}

JNIEXPORT jstring JNICALL Java_com_tencent_aesandmd5_MainActivity_hello(JNIEnv *env, jclass type) {

    LOGW("%s", md5("hello"));
    char *string = base64Encode("hello", 5);
    LOGW("%s", string);
    char *decode = base64Decode(string, strlen(string));
    LOGW("%s", decode);
    char *encrypt_str = encrypt("hello");
    LOGW("111 %s", encrypt_str);
    char *decrypt_str = decrypt(encrypt_str);
    LOGW("222 %s", decrypt_str);

    return (*env)->NewStringUTF(env, "hello from Jni");
}

