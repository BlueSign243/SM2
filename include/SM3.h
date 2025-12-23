#ifndef SM3_H
#define SM3_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* 常量定义 */
#define SM3_DIGEST_SIZE 32 /* SM3输出摘要长度（字节）*/
#define SM3_BLOCK_SIZE  64 /* SM3分组长度（字节）*/
#define SM3_STATE_WORDS 8  /* 状态寄存器数量 */

/* 错误码定义 */
#define SM3_SUCCESS        0  /* 成功 */
#define SM3_NULL_PTR       -1 /* 空指针错误 */
#define SM3_INVALID_LENGTH -2 /* 无效长度错误 */
#define SM3_INTERNAL_ERROR -3 /* 内部错误 */

/* SM3上下文结构体 */
typedef struct {
    uint32_t state[SM3_STATE_WORDS]; /* 当前哈希状态 */
    uint64_t total_len;              /* 已处理消息总长度（字节） */
    uint8_t block[SM3_BLOCK_SIZE];   /* 消息缓冲区（按字节存储） */
    size_t block_len;                /* 缓冲区中有效数据长度（字节） */
} SM3_CTX;

/**
 * @brief 初始化SM3上下文
 * @param ctx SM3上下文指针
 * @return 成功返回SM3_SUCCESS，失败返回错误码
 */
int SM3_Init(SM3_CTX *ctx);

/**
 * @brief 清理SM3上下文
 * @param ctx SM3上下文指针
 * @return 成功返回SM3_SUCCESS，失败返回错误码
 */
int SM3_Clean(SM3_CTX *ctx);

/**
 * @brief 处理输入数据（可多次调用）
 * @param ctx SM3上下文指针
 * @param data 输入数据指针
 * @param len 输入数据长度（字节）
 * @return 成功返回SM3_SUCCESS，失败返回错误码
 */
int SM3_Update(SM3_CTX *ctx, const uint8_t *data, size_t len);

/**
 * @brief 生成最终哈希值
 * @param ctx SM3上下文指针
 * @param digest 输出摘要缓冲区（至少32字节）
 * @return 成功返回SM3_SUCCESS，失败返回错误码
 */
int SM3_Final(SM3_CTX *ctx, uint8_t digest[SM3_DIGEST_SIZE]);

/**
 * @brief 一次性计算SM3哈希值
 * @param data 输入数据指针
 * @param len 输入数据长度
 * @param digest 输出摘要缓冲区
 * @return 成功返回SM3_SUCCESS，失败返回错误码
 */
int SM3(const uint8_t *data, size_t len, uint8_t digest[SM3_DIGEST_SIZE]);

/**
 * @brief SM3压缩函数（处理一个消息分组）
 * @param state 当前状态（输入输出参数）
 * @param block 消息分组（64字节）
 */
void SM3_Compress(uint32_t state[SM3_STATE_WORDS], const uint8_t block[SM3_BLOCK_SIZE]);

/**
 * @brief 填充消息
 * @param ctx SM3上下文指针
 */
void SM3_PadMessage(SM3_CTX *ctx);

#endif