#include "SM2.h"
#include <stdint.h>
#include <stdio.h>

int main() {
    int ret, success = 0;
    group g;
    SM2_PRI_KEY pri_key;
    SM2_PUB_KEY pub_key;
    SM2_SIG sig;
    char *msg = "message digest";
    char *id = "ALICE123@YAHOO.COM";

    for (int i = 0; i < 100; i++) {
        ret = SM2_GenerateKeyPair(&pri_key, &pub_key, &g);
        if (ret != SM2_SUCCESS)
            break;

        ret = SM2_Sign(&pri_key, &g, (uint8_t *)msg, strlen(msg), (uint8_t *)id, strlen(id), &sig);
        if (ret != SM2_SUCCESS)
            break;

        ret = SM2_Verify(&pub_key, &g, (uint8_t *)msg, strlen(msg), (uint8_t *)id, strlen(id), &sig);
        if (ret == SM2_SUCCESS)
            success++;
    }
    printf("Test done, success %d / 100.\n", success);
    return 0;
}
