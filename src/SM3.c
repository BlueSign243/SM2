#include "SM3.h"
#include <stdlib.h>
#include <string.h>

/* 循环左移宏定义 */
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* 布尔函数定义 */
#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define GG1(x, y, z) (((x) & (y)) | ((~x) & (z)))

/* 置换函数定义 */
#define P0(x) ((x) ^ ROTL(x, 9) ^ ROTL(x, 17))
#define P1(x) ((x) ^ ROTL(x, 15) ^ ROTL(x, 23))

/* SM3初始哈希值 */
static const uint32_t SM3_INITIAL_STATE[SM3_STATE_WORDS] = {0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
                                                            0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e};

/* SM3常量表 */
static const uint32_t SM3_TJ[64] = {
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a};

int SM3_Init(SM3_CTX *ctx) {
    /* 检查输入参数 */
    if (ctx == NULL)
        return SM3_NULL_PTR;

    memcpy(ctx->state, SM3_INITIAL_STATE, sizeof(SM3_INITIAL_STATE));
    ctx->total_len = 0;
    memset(ctx->block, 0, sizeof(ctx->block));
    ctx->block_len = 0;

    return SM3_SUCCESS;
}

int SM3_Clean(SM3_CTX *ctx) {
    /* 检查输入参数 */
    if (ctx == NULL)
        return SM3_NULL_PTR;

    memset(ctx->state, 0, sizeof(ctx->state));
    ctx->total_len = 0;
    memset(ctx->block, 0, sizeof(ctx->block));
    ctx->block_len = 0;

    return SM3_SUCCESS;
}

int SM3_Update(SM3_CTX *ctx, const uint8_t *data, size_t len) {
    /* 检查输入参数 */
    if (ctx == NULL || data == NULL)
        return SM3_NULL_PTR;

    /* 空数据直接返回成功 */
    if (len == 0)
        return SM3_SUCCESS;

    /* 更新总长度 */
    ctx->total_len += len;

    /* 如果缓冲区中有数据，先处理缓冲区中的数据 */
    if (ctx->block_len > 0) {
        /* 计算可以填充到缓冲区中的数据量 */
        size_t copy_len = SM3_BLOCK_SIZE - ctx->block_len;
        if (copy_len > len)
            copy_len = len;

        /* 将数据复制到缓冲区 */
        memcpy(ctx->block + ctx->block_len, data, copy_len);
        ctx->block_len += copy_len;
        data += copy_len;
        len -= copy_len;

        /* 如果缓冲区已满，处理这个完整的数据块 */
        if (ctx->block_len == SM3_BLOCK_SIZE) {
            SM3_Compress(ctx->state, ctx->block);
            ctx->block_len = 0;
        }
    }

    /* 处理完整的数据块（64字节） */
    while (len >= SM3_BLOCK_SIZE) {
        SM3_Compress(ctx->state, data);
        data += SM3_BLOCK_SIZE;
        len -= SM3_BLOCK_SIZE;
    }

    /* 将剩余数据复制到缓冲区 */
    if (len > 0) {
        memcpy(ctx->block + ctx->block_len, data, len);
        ctx->block_len += len;
    }

    return SM3_SUCCESS;
}

int SM3_Final(SM3_CTX *ctx, uint8_t digest[SM3_DIGEST_SIZE]) {
    /* 检查输入参数 */
    if (ctx == NULL || digest == NULL)
        return SM3_NULL_PTR;

    /* 对缓冲区中的数据进行填充 */
    SM3_PadMessage(ctx);

    /* 处理填充后的数据块 */
    if (ctx->block_len > 0) {
        /* 如果填充后缓冲区仍不满一个块，说明需要多处理一个块 */
        if (ctx->block_len < SM3_BLOCK_SIZE)
            return SM3_INTERNAL_ERROR;

        /* 处理填充后的完整块 */
        SM3_Compress(ctx->state, ctx->block);
        ctx->block_len = 0;
    }

    /* 将哈希状态转换为大端序字节数组 */
    for (int i = 0; i < SM3_STATE_WORDS; i++) {
        digest[i * 4] = (ctx->state[i] >> 24) & 0xFF;
        digest[i * 4 + 1] = (ctx->state[i] >> 16) & 0xFF;
        digest[i * 4 + 2] = (ctx->state[i] >> 8) & 0xFF;
        digest[i * 4 + 3] = ctx->state[i] & 0xFF;
    }

    return SM3_SUCCESS;
}

int SM3(const uint8_t *data, size_t len, uint8_t digest[SM3_DIGEST_SIZE]) {
    SM3_CTX ctx;
    int ret;

    /* 初始化SM3上下文 */
    ret = SM3_Init(&ctx);
    if (ret != SM3_SUCCESS)
        return ret;

    /* 更新SM3上下文 */
    ret = SM3_Update(&ctx, data, len);
    if (ret != SM3_SUCCESS)
        return ret;

    /* 计算最终哈希值 */
    ret = SM3_Final(&ctx, digest);
    if (ret != SM3_SUCCESS)
        return ret;

    return SM3_SUCCESS;
}

void SM3_PadMessage(SM3_CTX *ctx) {
    size_t original_len = ctx->block_len;
    size_t pad_len;

    /* 计算需要填充的长度 */
    if (original_len < SM3_BLOCK_SIZE - 8) {
        /* 情况1：可以在当前块内完成填充 */
        pad_len = SM3_BLOCK_SIZE - 8 - original_len;

        /* 添加第一个字节：0x80 (10000000) */
        ctx->block[ctx->block_len++] = 0x80;

        /* 填充0字节 */
        if (pad_len > 1) {
            memset(ctx->block + ctx->block_len, 0, pad_len - 1);
            ctx->block_len += pad_len - 1;
        }

        /* 添加消息长度（64位，大端序） */
        uint64_t bit_len = ctx->total_len * 8; /* 转换为比特数 */
        for (int i = 0; i < 8; i++)
            ctx->block[ctx->block_len + 7 - i] = (bit_len >> (i * 8)) & 0xFF;

        ctx->block_len += 8;
    } else {
        /* 情况2：需要两个块完成填充 */

        /* 第一个块：添加0x80并填充到块末尾 */
        ctx->block[ctx->block_len++] = 0x80;

        /* 填充第一个块的剩余部分 */
        size_t first_block_pad = SM3_BLOCK_SIZE - ctx->block_len;
        if (first_block_pad > 0) {
            memset(ctx->block + ctx->block_len, 0, first_block_pad);
            ctx->block_len += first_block_pad;
        }

        /* 处理第一个块 */
        SM3_Compress(ctx->state, ctx->block);

        /* 准备第二个块 */
        ctx->block_len = 0;
        memset(ctx->block, 0, SM3_BLOCK_SIZE);

        /* 第二个块：填充0字节 */
        size_t second_block_pad = SM3_BLOCK_SIZE - 8; /* 第二个块需要填充到64-8=56字节 */
        if (second_block_pad > 0) {
            memset(ctx->block, 0, second_block_pad);
            ctx->block_len += second_block_pad;
        }

        /* 添加消息长度（64位，大端序） */
        uint64_t bit_len = ctx->total_len * 8; /* 转换为比特数 */
        for (int i = 0; i < 8; i++)
            ctx->block[ctx->block_len + 7 - i] = (bit_len >> (i * 8)) & 0xFF;

        ctx->block_len += 8;
    }
}

void SM3_Compress(uint32_t state[SM3_STATE_WORDS], const uint8_t block[SM3_BLOCK_SIZE]) {
    uint32_t W[68];                  /* 消息扩展后的字 */
    uint32_t W1[64];                 /* 用于压缩的字 */
    uint32_t A, B, C, D, E, F, G, H; /* 工作变量 */
    uint32_t SS1, SS2, TT1, TT2;
    int j;

    for (j = 0; j < 16; j++) {
        W[j] = (uint32_t)(block[j * 4]) << 24 | (uint32_t)(block[j * 4 + 1]) << 16 | (uint32_t)(block[j * 4 + 2]) << 8 |
               (uint32_t)(block[j * 4 + 3]);
    }

    /* 扩展16个字到68个字 */
    for (j = 16; j < 68; j++)
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15)) ^ ROTL(W[j - 13], 7) ^ W[j - 6];

    /* 生成W1数组 */
    for (j = 0; j < 64; j++)
        W1[j] = W[j] ^ W[j + 4];

    /* 初始化工作变量 */
    A = state[0];
    B = state[1];
    C = state[2];
    D = state[3];
    E = state[4];
    F = state[5];
    G = state[6];
    H = state[7];

    /* 压缩函数主循环 */
    for (j = 0; j < 64; j++) {
        /* 计算SS1和SS2 */
        SS1 = ROTL(ROTL(A, 12) + E + ROTL(SM3_TJ[j], j), 7);
        SS2 = SS1 ^ ROTL(A, 12);

        /* 计算TT1和TT2 */
        if (j < 16) {
            TT1 = FF0(A, B, C) + D + SS2 + W1[j];
            TT2 = GG0(E, F, G) + H + SS1 + W[j];
        } else {
            TT1 = FF1(A, B, C) + D + SS2 + W1[j];
            TT2 = GG1(E, F, G) + H + SS1 + W[j];
        }

        /* 更新工作变量 */
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }

    /* 更新状态 */
    state[0] ^= A;
    state[1] ^= B;
    state[2] ^= C;
    state[3] ^= D;
    state[4] ^= E;
    state[5] ^= F;
    state[6] ^= G;
    state[7] ^= H;
}
