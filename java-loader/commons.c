#include "commons.h"
#include <stdio.h>

void DEBUG_SHELLCODE(unsigned char *charArray, int length) {
    unsigned char *ptr = charArray;
    printf("########## DEBUG FROM C ##########\n");
    int max = 0;
    for (int i = 0; i < length; i++) {
        max++;
        unsigned char value = *ptr;
        printf("%02x ", value);
        ptr++;
        if (max > 30) {
            printf("\n");
            max = 0;
        }
    }
    printf("\n##################################\n");
}