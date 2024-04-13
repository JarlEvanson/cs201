#include "BHeap.cpp"

#include <climits>
#include <cstdio>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <cassert>

__AFL_FUZZ_INIT();

int main() {
    __AFL_INIT();

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while(__AFL_LOOP(UINT_MAX)) {
        unsigned int len = __AFL_FUZZ_TESTCASE_LEN;
        
        BHeap<int> heap;

        if(len < sizeof(int)) continue;

        int lowest = INT_MAX;

        for(int i = 0; i < len / sizeof(int); i++) {
            int value = ((int) buf[i * sizeof(int)]) | (((int) buf[i * sizeof(int) + 1]) << 8) | (((int) buf[i * sizeof(int) + 2]) << 16) | (((int) buf[i * sizeof(int) + 3]) << 24);
            if(value < lowest) {
                lowest = value;
            }
            heap.insert(value);
            assert(heap.peekKey() == lowest);
        }

        while(!heap.isEmpty()) {
            int extracted_value = heap.extractMin();

            assert(extracted_value >= lowest);
            lowest = extracted_value;
        }
    }

    return 0;
}