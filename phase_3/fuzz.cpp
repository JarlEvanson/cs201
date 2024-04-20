#include "BHeap.cpp"

#include <climits>
#include <cstdio>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <cassert>
#include <cstdint>

#include <vector>
#include <queue>

#ifndef __AFL_FUZZ_TESTCASE_LEN
  ssize_t fuzz_len;
  #define __AFL_FUZZ_TESTCASE_LEN fuzz_len
  unsigned char fuzz_buf[1024000];
  #define __AFL_FUZZ_TESTCASE_BUF fuzz_buf
  #define __AFL_FUZZ_INIT() void sync(void);
  #define __AFL_LOOP(x) ((fuzz_len = read(0, fuzz_buf, sizeof(fuzz_buf))) > 0 ? 1 : 0)
  #define __AFL_INIT() sync()
#endif

__AFL_FUZZ_INIT();

int main() {
    __AFL_INIT();

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while(__AFL_LOOP(UINT_MAX)) {
        unsigned int len = __AFL_FUZZ_TESTCASE_LEN;
        unsigned int byte_index = 0;
        
        std::vector<BHeap<uint32_t>> heaps = std::vector<BHeap<uint32_t>>();
        std::vector comparison_heaps = std::vector<std::priority_queue<uint32_t, std::vector<uint32_t>, std::greater<uint32_t>>>();

        auto comparison = std::priority_queue<uint32_t, std::vector<uint32_t>, std::greater<uint32_t>>();
        comparison_heaps.push_back(comparison);

        BHeap<uint32_t> heap;
        heaps.push_back(heap);

        while(byte_index < len) {
            if(byte_index + 5 < byte_index || byte_index + 5 > len) {
                goto next_fuzz;
            }

            unsigned char item_kind = buf[byte_index];
            byte_index += 1;

            uint32_t heap_index = (((uint32_t) buf[byte_index * sizeof(uint32_t)])
                | (((uint32_t) buf[byte_index * sizeof(uint32_t) + 1]) << 8)
                | (((uint32_t) buf[byte_index * sizeof(uint32_t) + 2]) << 16)
                | (((uint32_t) buf[byte_index * sizeof(uint32_t) + 3]) << 24)) % heaps.size();
            
            byte_index += 4;

            uint32_t value = 0;
            uint32_t other_heap = 0;

            switch(item_kind) {
                case 0:
                    if(byte_index + 4 < len || byte_index + 4 > len) {
                        goto next_fuzz;
                    }

                    value = ((uint32_t) buf[byte_index * sizeof(uint32_t)])
                        | (((uint32_t) buf[byte_index * sizeof(uint32_t) + 1]) << 8)
                        | (((uint32_t) buf[byte_index * sizeof(uint32_t) + 2]) << 16)
                        | (((uint32_t) buf[byte_index * sizeof(uint32_t) + 3]) << 24);

                    std::cout << "Inserting " << value << " into " << heap_index << '\n';

                    byte_index += 4;

                    heaps[heap_index].insert(value);
                    comparison_heaps[heap_index].push(value);

                    assert(heaps[heap_index].peekKey() == comparison_heaps[heap_index].top());

                    break;
                case 1:
                    if(comparison_heaps[heap_index].empty()) {
                        continue;
                    }
                    std::cout << "Extracting minimum from " << heap_index << '\n';

                    assert(heaps[heap_index].extractMin() == comparison_heaps[heap_index].top());
                    comparison_heaps[heap_index].pop();

                    break;
                case 2:
                    if(byte_index + 4 < len || byte_index + 4 > len) {
                        goto next_fuzz;
                    }

                    other_heap = (((uint32_t) buf[byte_index * sizeof(uint32_t)])
                        | (((uint32_t) buf[byte_index * sizeof(uint32_t) + 1]) << 8)
                        | (((uint32_t) buf[byte_index * sizeof(uint32_t) + 2]) << 16)
                        | (((uint32_t) buf[byte_index * sizeof(uint32_t) + 3]) << 24)) % heaps.size();

                    std::cout << "Merging " << other_heap << " into " << heap_index << '\n';

                    byte_index += 4;

                    heaps[heap_index].merge(heaps[other_heap]);
                    {
                        if(heap_index != other_heap) {
                            while(!comparison_heaps[other_heap].empty()) {
                                comparison_heaps[heap_index].push(comparison_heaps[other_heap].top());
                                comparison_heaps[other_heap].pop();
                            }
                        } else {
                            while(!comparison_heaps[heap_index].empty()) comparison_heaps[heap_index].pop();
                        }
                        
                    }

                    assert(heaps[other_heap].element_count() == 0 && heaps[other_heap].element_count() == comparison_heaps[other_heap].size());
                    assert(heaps[heap_index].element_count() == comparison_heaps[heap_index].size());
                    if(heaps[heap_index].element_count() == 0) {
                        continue;
                    }
                    assert(heaps[heap_index].peekKey() == comparison_heaps[heap_index].top());
                    assert(heaps[other_heap].isEmpty());

                    break;
                case 3:
                    std::cout << "Copying " << heap_index << '\n';

                    heaps.push_back(heaps[heap_index]);
                    comparison_heaps.push_back(comparison_heaps[heap_index]);

                    break;
                default:
                    continue;
            }
        }

    next_fuzz:
        ;
    }

    return 0;
}