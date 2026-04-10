#include "aes256.h"
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/err.h>
#include <openssl/x509.h> 
#define KEY_SIZE 32
#define IV_SIZE 16
#define TAG_SIZE 16       // GCM 认证标签为 16 字节

const unsigned char iv[IV_SIZE] = {
    0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
    0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f
};

// HEX 编码函数：将字节数组编码为十六进制字符串
static void hex_encode(const unsigned char *in, size_t len, char *out) {
    for (size_t i = 0; i < len; ++i) {
        sprintf(out + (i * 2), "%02x", in[i]);
    }
    out[len * 2] = '\0';
}

// HEX 解码函数：将十六进制字符串解码为字节数组
static void hex_decode(const char *in, unsigned char *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(in + 2 * i, "%2hhx", &out[i]);
    }
}

// AES-256 CBC 模式加密函数
int aes256_encrypt(const char *input, const unsigned char *key, char **out_hex) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // 创建加密上下文
    unsigned char ciphertext[1024];             // 临时密文缓冲区
    int len = 0, ciphertext_len = 0;

    // 初始化加密操作（使用 AES-256-CBC）
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, (const unsigned char *)input, strlen(input));
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len); // 处理尾部
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx); // 清理上下文

    // 为 HEX 输出分配内存（每个字节 2 个字符）
    *out_hex = malloc(ciphertext_len * 2 + 1);
    if (!*out_hex) return 0;

    // HEX 编码输出
    hex_encode(ciphertext, ciphertext_len, *out_hex);
    return ciphertext_len;
}

// AES-256 CBC 模式解密函数
int aes256_decrypt(const char *hex_input, const unsigned char *key, char **output,int intput_len) {
    size_t ciphertext_len = intput_len / 2;
    printf("================================aes256_decrypt:%ld==========================================\n",ciphertext_len);
    unsigned char *ciphertext = malloc(ciphertext_len); // 解码后的密文
    if (!ciphertext) return 0;

    // HEX 解码密文
    hex_decode(hex_input, ciphertext, strlen(hex_input) / 2);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char plaintext[10240] = {0}; // 明文缓冲区
    int len_out = 0, plaintext_len = 0;

    // 初始化解密操作
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len_out, ciphertext, ciphertext_len);
    plaintext_len = len_out;
    EVP_DecryptFinal_ex(ctx, plaintext + len_out, &len_out); // 处理尾部
    plaintext_len += len_out;
    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    printf("========================plaintext_len:%d=====================================\n",plaintext_len);
    // 分配输出明文内存
    *output = malloc(plaintext_len + 1);
    if (!*output) return 0;

    // 拷贝明文并加终止符
    memcpy(*output, plaintext, plaintext_len);
    (*output)[plaintext_len] = '\0';
    return plaintext_len;
}

// AES-256 GCM 模式加密函数
int aes256_gcm_encrypt(const char *input, 
                       const unsigned char *key,
                       const char *aad, 
                       int aad_len, 
                       int input_len,
                       char **out_hex, 
                       char **tag_hex)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) return 0;
    unsigned char ciphertext[10240]; // 密文缓冲区
    unsigned char tag[TAG_SIZE];    // 认证标签
    int len = 0, ciphertext_len = 0;
    int ret = -1;
    // 初始化加密操作
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);

    // 设置 IV 长度
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL);

    // 初始化 key 和 IV
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    // 提供 AAD (附加认证数据)
    if (aad && aad_len > 0)
    {
        EVP_EncryptUpdate(ctx, NULL, &len,(const unsigned char *) aad, aad_len);
    }

    // 加密明文
    ret = EVP_EncryptUpdate(ctx, ciphertext, &len, (const unsigned char *)input, input_len);
    if(ret != 1) return 0;
    ciphertext_len = len;

    // 完成加密
    ret = EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    if(ret != 1) return 0;
    ciphertext_len += len;

    // 获取认证标签
    ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag);
    if(ret != 1) return 0;
    if(ctx)
    {
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }

    // 为 HEX 输出分配内存
    *out_hex = malloc(ciphertext_len * 2 + 1);
    *tag_hex = malloc(TAG_SIZE * 2 + 1);
    if (!*out_hex || !*tag_hex)
    {
        if (*out_hex)
            free(*out_hex);
        if (*tag_hex)
            free(*tag_hex);
        return 0;
    }

    // HEX 编码输出
    hex_encode(ciphertext, ciphertext_len, *out_hex);
    hex_encode(tag, TAG_SIZE, *tag_hex);
    return ciphertext_len;
}

// AES-256 GCM 模式解密函数
int aes256_gcm_decrypt(const char *hex_input, 
                       const uint32_t data_len, 
                       const unsigned char *key, 
                       const char *aad, const char *hex_tag, 
                       char **output)
{
    if(hex_input == NULL || key == NULL || iv == NULL || aad == NULL || hex_tag == NULL ) return 0;
    size_t ciphertext_len = data_len / 2;
    unsigned char *ciphertext = malloc(ciphertext_len);
    unsigned char tag[TAG_SIZE];
    int aad_len = aad ? strlen(aad) : 0;

    if (!ciphertext)
        return 0;

    // HEX 解码密文和标签
    hex_decode(hex_input, ciphertext, ciphertext_len);
    hex_decode(hex_tag, tag, TAG_SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char plaintext[10240] = {0}; // 明文缓冲区
    int len_out = 0, plaintext_len = 0;

    // 初始化解密操作
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    // 提供 AAD
    if (aad_len > 0)
    {
        EVP_DecryptUpdate(ctx, NULL, &len_out, (const unsigned char *)aad, aad_len);
    }

    // 解密密文
    EVP_DecryptUpdate(ctx, plaintext, &len_out, ciphertext, ciphertext_len);
    plaintext_len = len_out;

    // 设置预期的认证标签
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag);

    // 完成解密并验证标签
    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len_out, &len_out);
    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);

    if (ret <= 0)
    {
        printf("\naes256_gcm_decrypt===============================error\n");
        // 认证失败
        return 0;
    }
    plaintext_len += len_out;

    // 分配输出内存
    *output = malloc(plaintext_len + 1);
    if (!*output)
        return -1;

    // 拷贝明文并加终止符
    memcpy(*output, plaintext, plaintext_len);
    (*output)[plaintext_len] = '\0';
    return plaintext_len;
}


/*
 * 生成ECDH密钥对
*/
EC_KEY *generate_ecdh_key()
{
    const char* curve_name = OBJ_nid2sn(CURVE_NAME);
    printf("BLE Curve name: %s\n", curve_name ? curve_name : "Unknown");
    if(curve_name == NULL)
    {
        return NULL;
    }
    EC_KEY *key = EC_KEY_new_by_curve_name(CURVE_NAME);
    if (!key) {
        printf("BLE generate_ecdh_key EC_KEY_new_by_curve_name failed\n");
        return NULL;
    }
     
    if (!EC_KEY_generate_key(key)) {
        printf("BLE generate_ecdh_key EC_KEY_generate_key failed\n");
        EC_KEY_free(key);  // 释放失败时的内存
        return NULL;
    }
    // 检查密钥是否合法
     if (!EC_KEY_check_key(key)) {
        EC_KEY_free(key); 
        printf("BLE generate_ecdh_key EC_KEY_check_key failed\n");
        return NULL;
    }
    return key;  // 返回新生成的密钥对
}
EC_KEY *parse_der_public_key(const unsigned char *der_data, size_t der_len) {
    const unsigned char *p = der_data;
    EC_KEY *ec_key = d2i_EC_PUBKEY(NULL, &p, der_len);
    if (!ec_key) {
        // 处理错误：打印OpenSSL错误队列
        printf("Error parsing DER public key: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }
    return ec_key;
}
/**
 * 生成公钥
 */
unsigned char *export_public_key(EC_KEY *key, size_t *len)
{
    // 检查密钥是否合法
    if (!EC_KEY_check_key(key)) {
        printf("BLE export_public_key EC_KEY_check_key failed\n");
        return NULL;
    }
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const EC_POINT *point = EC_KEY_get0_public_key(key);

    if (!group || !point) {
        printf("BLE export_public_key Failed to get group or public point\n");
        return NULL;
    }
     
    // 计算未压缩格式公钥长度
    *len = EC_POINT_point2oct(group, point,
                              POINT_CONVERSION_COMPRESSED,
                              NULL, 0, NULL);
    if (*len == 0)
        printf("BLE export_public_key Public key length calculation failed\n");

    // 分配内存并导出
    unsigned char *buf = OPENSSL_malloc(*len + 1);
    if (!buf)
        printf("BLE export_public_key Memory allocation failed\n");

    if (!EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED,
                            buf, *len, NULL))
    {
        OPENSSL_free(buf);
        printf("BLE export_public_key Public key export failed\n");
    }
    printf("BLE export_public_key Public key exported successfully len:%ld\n", *len);
    buf[*len] = '\0';
    return buf;
}



/**
 * 计算共享密钥
 */
int compute_shared_secret(EC_KEY *local_key,
                                     const unsigned char *peer_pub,
                                     size_t peer_der_len,
                                     char* shared_key)
{
    // 参数检查
    if (!local_key || !peer_pub || !shared_key) {
        printf("BLE Error: Invalid input parameters\n");
        return 0;
    }

    // 检查本地密钥有效性
    if (!EC_KEY_check_key(local_key)) {
        printf("BLE Error: Invalid local EC key\n");
        return 0;
    }

    const EC_GROUP *group = EC_KEY_get0_group(local_key);
    if (!group) {
        printf("BLE Error: Failed to get EC group\n");
        return 0;
    }

    // 创建并解析对端公钥点
    EC_POINT *peer_point = EC_POINT_new(group);
    if (!peer_point) {
        printf("BLE Error: Failed to create EC_POINT\n");
        return 0;
    }

    // 解析未压缩格式的裸公钥
    if (0 == EC_POINT_oct2point(group, peer_point, peer_pub, peer_der_len, NULL )) {
        printf("BLE Error: Failed to parse uncompressed public key (len=%zu)\n", peer_der_len);
        EC_POINT_free(peer_point);
        return 0;
    }
  

    // 验证对端公钥点是否在曲线上
    if (!EC_POINT_is_on_curve(group, peer_point, NULL)) {
        printf("BLE Error: Peer public key is not on curve\n");
        EC_POINT_free(peer_point);
        return 0;
    }

    // 计算共享密钥
    unsigned char shared_secret[32]; // 对于常见曲线(如secp256r1)足够
    int secret_len = ECDH_compute_key(shared_secret, sizeof(shared_secret), 
                                    peer_point, local_key, NULL);
    
    EC_POINT_free(peer_point);

    if (secret_len <= 0) {
        printf("BLE Error: ECDH computation failed\n");
        return 0;
    }

    memcpy(shared_key, shared_secret, secret_len);
    printf("BLE Success: Shared secret computed (len=%d)\n", secret_len);
    return secret_len;
}
