#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    int i = 0;
    char buf1[16];
    char buf2[128];

    if(size > 10) {
        if(data[0] == 'a') {
            memcpy(buf1, buf2, sizeof(buf2));
        }
        if(data[0] == 'b') {
            int j = 0;
            while(true) {
                j++;
            }
        }
    }
    else {
        i++;    
    }

    return 0;
}
