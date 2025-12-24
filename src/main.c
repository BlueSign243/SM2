#include "SM2.h"
#include <stdint.h>
#include <stdio.h>

int main() {
    int ret, success = 0;
    SM2_CTX ctx;
    SM2_SIG sig;
    char *msg = "message digest";
    char *id = "ALICE123@YAHOO.COM";
    SM2_Init(&ctx);

    for (int i = 0; i < 100; i++) {
        ret = SM2_GenerateKeyPair(&ctx);
        if (ret != SM2_SUCCESS)
            break;

        ret = SM2_Sign(&ctx, (uint8_t *)msg, strlen(msg), (uint8_t *)id, strlen(id), &sig);
        if (ret != SM2_SUCCESS)
            break;

        ret = SM2_Verify(&ctx, (uint8_t *)msg, strlen(msg), (uint8_t *)id, strlen(id), &sig);
        if (ret == SM2_SUCCESS)
            success++;
    }
    printf("Test done, success %d / 100.\n", success);
    return 0;
}
