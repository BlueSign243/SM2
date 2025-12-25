#ifndef SM2_H
#define SM2_H

#include "bn.h"
#include "ec.h"
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

/* SM2算法错误码 */
#define SM2_SUCCESS        0  /* 成功 */
#define SM2_NULL_PTR       -1 /* 空指针错误 */
#define SM2_INVALID_SIG    -2 /* 无效签名 */
#define SM2_INVALID_CIPHER -3 /* 无效密文 */

/* SM2私钥结构 */
typedef struct {
    bn_t da; /* 私钥 */
} SM2_PRI_KEY;

/* SM2公钥结构 */
typedef struct {
    point pa; /* 公钥 */
} SM2_PUB_KEY;

/* SM2签名结构 */
typedef struct {
    bn_t r; /* 签名r分量 */
    bn_t s; /* 签名s分量 */
} SM2_SIG;

/**
 * @brief 生成SM2密钥对
 * @param pri_key 私钥
 * @param pub_key 公钥
 * @param g       椭圆曲线参数
 * @return 错误码
 */
int SM2_GenerateKeyPair(SM2_PRI_KEY *pri_key, SM2_PUB_KEY *pub_key, group *g);

/**
 * @brief SM2数字签名
 * @param pri_key 私钥
 * @param g       椭圆曲线参数
 * @param msg     待签名消息
 * @param mlen    消息长度
 * @param id      用户标识
 * @param entl    用户标识长度
 * @param sig     签名
 * @return 错误码
 */
int SM2_Sign(SM2_PRI_KEY *pri_key, group *g, const uint8_t *msg, size_t mlen, uint8_t *id, size_t entl, SM2_SIG *sig);

/**
 * @brief SM2签名验证
 * @param pub_key 公钥
 * @param g       椭圆曲线参数
 * @param msg     原始消息
 * @param mlen    消息长度
 * @param sig     待验证签名
 * @return 错误码
 */
int SM2_Verify(SM2_PUB_KEY *pub_key, group *g, const uint8_t *msg, size_t mlen, uint8_t *id, size_t entl,
               const SM2_SIG *sig);

/**
 * @brief SM2加密
 * @param pub_key 公钥
 * @param plain   明文
 * @param plen    明文长度
 * @param cipher  密文
 * @param clen    密文长度
 * @return 错误码
 */
int SM2_Encrypt(SM2_PUB_KEY *pub_key, const uint8_t *plain, size_t plen, uint8_t *cipher, size_t *clen);

/**
 * @brief SM2解密
 * @param pri_key 私钥
 * @param cipher  密文
 * @param clen    密文长度
 * @param plain   明文
 * @param plen    明文长度
 * @return 错误码
 */
int SM2_Decrypt(SM2_PRI_KEY *pri_key, const uint8_t *cipher, size_t clen, uint8_t *plain, size_t *plen);

#endif