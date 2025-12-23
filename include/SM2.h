#ifndef SM2_H
#define SM2_H

#include "bn.h"
#include "point.h"
#include <stddef.h>
#include <stdint.h>

/* SM2算法相关常量定义 */
#define SM2_CURVE_PARAM_P  "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3"
#define SM2_CURVE_PARAM_A  "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"
#define SM2_CURVE_PARAM_B  "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A"
#define SM2_CURVE_PARAM_GX "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"
#define SM2_CURVE_PARAM_GY "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"
#define SM2_CURVE_PARAM_N  "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7"

/* Montgomery预计算参数定义 */
#define SM2_MONT_R     "7ABD2961B3FBB0E71746DBCA40900821BA8D7C6EA3BAAE828DD12474F70E203D"
#define SM2_MONT_R2    "0AE55229283CD96AEE4D87DA90D8C66CEB372DA83FC9C6363D579C46F6DE18F2"
#define SM2_MONT_PINV  "ACE8C019117B91A87C85E2872C08DD0D3B8465BC9C2E9D06A2A0380C50F77715"
#define SM2_MONT_R_INV "5A0210C4081F3AB5440715F30A514C89BFE7AF848398B0E9369D3D0DF14C16C9"

/* SM2算法参数大小（字节） */
#define SM2_KEY_SIZE    32 /* 私钥/公钥大小（256位） */
#define SM2_SIG_SIZE    64 /* 签名大小（64字节） */
#define SM2_CIPHER_SIZE 97 /* 密文开销（97字节） */

/* SM2算法错误码 */
#define SM2_SUCCESS        0  /* 成功 */
#define SM2_NULL_PTR       -1 /* 空指针错误 */
#define SM2_INVALID_PARAM  -2 /* 无效参数 */
#define SM2_INVALID_SIG    -3 /* 无效签名 */
#define SM2_INVALID_CIPHER -4 /* 无效密文 */
#define SM2_INVALID_LENGTH -5 /* 无效长度 */
#define SM2_INTERNAL_ERROR -6 /* 内部错误 */

/* SM2密钥对结构 */
typedef struct {
    bn_t private_key; /* 私钥 */
    point public_key; /* 公钥 */
} SM2_KEYPAIR;

/* SM2签名结构 */
typedef struct {
    uint8_t r[SM2_KEY_SIZE]; /* 签名r分量 */
    uint8_t s[SM2_KEY_SIZE]; /* 签名s分量 */
} SM2_SIG;

/* SM2加密上下文结构 */
typedef struct {
    SM2_KEYPAIR keypair;    /* 密钥对 */
    uint8_t kdf_buffer[64]; /* KDF缓冲区 */
    size_t kdf_len;         /* KDF数据长度 */
} SM2_CTX;

/**
 * @brief 初始化SM2上下文
 * @param ctx SM2上下文指针
 * @return 错误码
 */
int SM2_Init(SM2_CTX *ctx);

/**
 * @brief 生成SM2密钥对
 * @param ctx SM2上下文指针
 * @return 错误码
 */
int SM2_GenerateKeyPair(SM2_CTX *ctx);

/**
 * @brief SM2数字签名
 * @param ctx  SM2上下文指针
 * @param msg  待签名消息
 * @param mlen 消息长度
 * @param id   用户标识
 * @param entl 用户标识长度
 * @param sig  签名输出缓冲区
 * @return 错误码
 */
int SM2_Sign(SM2_CTX *ctx, const uint8_t *msg, size_t mlen, uint8_t *id, size_t entl, SM2_SIG *sig);

/**
 * @brief SM2签名验证
 * @param ctx SM2上下文指针
 * @param msg 原始消息
 * @param mlen 消息长度
 * @param sig 待验证签名
 * @return 错误码（SM2_SUCCESS表示验证成功）
 */
int SM2_Verify(SM2_CTX *ctx, const uint8_t *msg, size_t mlen, const SM2_SIG *sig);

/**
 * @brief SM2加密
 * @param ctx SM2上下文指针
 * @param plain 明文
 * @param plen 明文长度
 * @param cipher 密文输出缓冲区
 * @param clen 密文长度（输出参数）
 * @return 错误码
 */
int SM2_Encrypt(SM2_CTX *ctx, const uint8_t *plain, size_t plen, uint8_t *cipher, size_t *clen);

/**
 * @brief SM2解密
 * @param ctx SM2上下文指针
 * @param cipher 密文
 * @param clen 密文长度
 * @param plain 明文输出缓冲区
 * @param plen 明文长度（输出参数）
 * @return 错误码
 */
int SM2_Decrypt(SM2_CTX *ctx, const uint8_t *cipher, size_t clen, uint8_t *plain, size_t *plen);

/**
 * @brief 清理SM2上下文
 * @param ctx SM2上下文指针
 */
void SM2_Clean(SM2_CTX *ctx);

#endif