#include "two4Tree.cpp"

#include <cstring>
#include <cstdio>
#include <cstdint>
#include <cstdlib>

typedef struct Input {
    unsigned char* buffer;
    size_t len;
} Input;

Input get_input(char* name) {
    FILE* input_file = fopen(name, "rb");
    if(input_file == NULL) {
        perror("input failed");
        exit(1);
    }

    if(fseek(input_file, 0, SEEK_END) != 0) {
        perror("length discovery failed");
        exit(1);
    }
    size_t size = ftell(input_file);
    if(size == -1) {
        perror("length discovery failed");
        exit(1);
    }
    if(fseek(input_file, 0, SEEK_SET) != 0) {
        perror("length discovery failed");
        exit(1);
    }
    if(size == 0) {
        fprintf(stderr, "input allocation failed\n");
        exit(1);
    }
    unsigned char* ptr = (unsigned char*) malloc(size * sizeof(unsigned char));
    if(ptr == NULL) {
        fprintf(stderr, "input allocation failed\n");
        exit(1);
    }

    size_t capacity = size;
    size_t len = 0;

    while(!feof(input_file)) {
        size_t chars_read = fread(ptr, sizeof(unsigned char), capacity - len + 1, input_file);
        if(chars_read == 0 && ferror(input_file) != 0) {
            perror("input file read failed");
            exit(1);
        }
        len += chars_read;
    }

    Input input;
    input.buffer = ptr;
    input.len = len;

    fclose(input_file);

    return input;
}

uint64_t inline static read_le_u64(unsigned char* buffer);
uint32_t inline static read_le_u32(unsigned char* buffer);
uint16_t inline static read_le_u16(unsigned char* buffer);

int main(int argc, char** argv) {
    if(argc <= 1) {
        fprintf(stderr, "application requires name of input file\n");
        return 1;
    }

    Input input = get_input(argv[1]);

    size_t byte_index = 0;

    CircularDynamicArray<two4Tree<uint32_t, uint32_t>> trees;

    trees.addEnd(two4Tree<uint32_t, uint32_t>());

    while(byte_index < input.len) {
        if(byte_index + 1 < byte_index || byte_index >= input.len ) {
            fprintf(stderr, "Buffer overflow\n");
            goto error;
        }

        unsigned char item_kind = input.buffer[byte_index];
        byte_index += 1;

        uint16_t tree_index;
        uint64_t rank;
        uint32_t key;
        uint32_t value;

        switch(item_kind) {
        case 0:
            #ifdef TEST
            fprintf(stdout, "Instruction at %u: ", byte_index - 1);
            #endif
            if(byte_index + 10 < byte_index || byte_index + 10 > input.len) {
                fprintf(stderr, "Buffer overflow\n");
                goto error;
            }

            tree_index = read_le_u16(&input.buffer[byte_index]) % trees.length();
            key = read_le_u32(&input.buffer[byte_index + 2]);
            value = read_le_u32(&input.buffer[byte_index] + 6);

            #ifdef TEST
            fprintf(stdout, "Insert %u with %u into %u\n", key, value, read_le_u16(&input.buffer[byte_index]) % trees.length());
            #endif

            byte_index += 10;

            trees[tree_index].insert(key, value);
            trees[tree_index].validate();
            break;
        case 1:
            #ifdef TEST
            fprintf(stdout, "Instruction at %u: ", byte_index - 1);
            #endif
            if(byte_index + 6 < byte_index || byte_index + 6 > input.len) {
                fprintf(stderr, "Buffer overflow\n");
                goto error;
            }
            
            tree_index = read_le_u16(&input.buffer[byte_index]) % trees.length();
            key = read_le_u32(&input.buffer[byte_index + 2]);

            #ifdef TEST
            fprintf(stdout, "Remove %u from %u\n", key, read_le_u16(&input.buffer[byte_index]) % trees.length());
            #endif

            byte_index += 6;

            trees[tree_index].remove(key);
            trees[tree_index].validate();
            break;
        case 2:
            #ifdef TEST
            fprintf(stdout, "Instruction at %u: ", byte_index - 1);
            #endif
            if(byte_index + 2 < byte_index || byte_index + 2 > input.len) {
                fprintf(stderr, "Buffer overflow\n");
                goto error;
            }

            tree_index = read_le_u16(&input.buffer[byte_index]) % trees.length();

            #ifdef TEST
            fprintf(stdout, "Copy %u\n", tree_index);
            #endif

            byte_index += 2;

            trees.addEnd(two4Tree<uint32_t, uint32_t>(trees[tree_index]));
            trees[tree_index + 1].validate();
            break;
        case 3:
            #ifdef TEST
            fprintf(stdout, "Instruction at %u: ", byte_index - 1);
            #endif
            if(byte_index + 6 < byte_index || byte_index + 6 > input.len) {
                fprintf(stderr, "Buffer overflow\n");
                goto error;
            }

            tree_index = read_le_u16(&input.buffer[byte_index]) % trees.length();
            key = read_le_u32(&input.buffer[byte_index + 2]);

            #ifdef TEST
            fprintf(stdout, "Rank of %u in %u\n", key, tree_index);
            #endif

            {
                trees[tree_index].validate();
                rank = (uint64_t) trees[tree_index].rank(key);
                if(rank == 0) {
                    continue;
                }
                #ifdef TEST
                fprintf(stdout, "Key at %lu is %u\n", rank, trees[tree_index].select(rank));
                #endif

                assert(trees[tree_index].select(rank) == key);
            }

            break;
        case 4:
            #ifdef TEST
            fprintf(stdout, "Instruction at %u: ", byte_index - 1);
            #endif
            if(byte_index + 6 < byte_index || byte_index + 6 > input.len) {
                fprintf(stderr, "Buffer overflow\n");
                goto error;
            }

            tree_index = read_le_u16(&input.buffer[byte_index]) % trees.length();
            if(trees[tree_index].size() == 0) {
                continue;
            }
            rank = (uint64_t) read_le_u32(&input.buffer[byte_index + 2]) % trees[tree_index].size() + 1;

            #ifdef TEST
            fprintf(stdout, "Key at %u in %u\n", rank, tree_index);
            #endif

            {
                key = trees[tree_index].select((int) rank);
                uint64_t test_rank = trees[tree_index].rank(key);
                assert(test_rank <= rank && rank < test_rank + trees[tree_index].duplicates(key));
            }

            break;
        default:
            fprintf(stderr, "Invalid Instruction\n");
            goto error;
        }
    }
    
    free(input.buffer);
    input.buffer = NULL;

    printf("Successful run\n");

    return 0;

    error:
    free(input.buffer);
    return 1;
}

uint64_t inline static read_le_u64(unsigned char* buffer) {
    return ((uint64_t) buffer[0]) 
    | (((uint64_t) buffer[1]) << 8)
    | (((uint64_t) buffer[2]) << 16)
    | (((uint64_t) buffer[3]) << 24)
    | (((uint64_t) buffer[4]) << 32)
    | (((uint64_t) buffer[5]) << 40)
    | (((uint64_t) buffer[6]) << 48)
    | (((uint64_t) buffer[7]) << 56);
}

uint32_t inline static read_le_u32(unsigned char* buffer) {
    return ((uint32_t) buffer[0])
    | (((uint32_t) buffer[1]) << 8)
    | (((uint32_t) buffer[2]) << 16)
    | (((uint32_t) buffer[3]) << 24);
}

uint16_t inline static read_le_u16(unsigned char* buffer) {
    return ((uint16_t) buffer[0])
    | (((uint16_t) buffer[1]) << 8);
}