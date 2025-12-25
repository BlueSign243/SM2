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

    // 初始化进度条
    char progress[51] = {0};
    for (int i = 0; i < 50; i++)
        progress[i] = '.';
    progress[50] = '\0';

    printf("SM2 Test Progress: [%s]\r", progress);
    fflush(stdout);

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

        // 更新进度条
        if ((i + 1) % 2 == 0)
            progress[(i + 1) / 2 - 1] = '#';
        printf("SM2 Test Progress: [%s] %d/100\r", progress, i + 1);
        fflush(stdout);
    }

    // 完成进度条
    printf("\nTest completed, success rate: %d / 100\n", success);

    if (success == 100)
        printf("All Test Cases Passed!\n");
    else
        printf("Some Test Cases Failed!\n");

    return 0;
}
