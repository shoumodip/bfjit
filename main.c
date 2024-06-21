#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

// Config
#define BF_JIT 1
#define BF_MEMORY 30000

#if BF_JIT
#    if !defined(__linux__) || !defined(__x86_64__)
#        error "JIT is only implemented for x86_64 Linux"
#    endif
#endif

// Defer
#define return_defer(value)                                                                        \
    do {                                                                                           \
        result = (value);                                                                          \
        goto defer;                                                                                \
    } while (0)

// Dynamic Array
#define DA_INIT_CAP 128

#define da_append(l, v)                                                                            \
    do {                                                                                           \
        if ((l)->count >= (l)->capacity) {                                                         \
            (l)->capacity = (l)->capacity == 0 ? DA_INIT_CAP : (l)->capacity * 2;                  \
            (l)->data = realloc((l)->data, (l)->capacity * sizeof(*(l)->data));                    \
        }                                                                                          \
                                                                                                   \
        (l)->data[(l)->count++] = (v);                                                             \
    } while (0)

#define da_append_many(l, v, c)                                                                    \
    do {                                                                                           \
        if ((l)->count + (c) > (l)->capacity) {                                                    \
            if ((l)->capacity == 0) {                                                              \
                (l)->capacity = DA_INIT_CAP;                                                       \
            }                                                                                      \
                                                                                                   \
            while ((l)->count + (c) > (l)->capacity) {                                             \
                (l)->capacity *= 2;                                                                \
            }                                                                                      \
                                                                                                   \
            (l)->data = realloc((l)->data, (l)->capacity * sizeof(*(l)->data));                    \
        }                                                                                          \
                                                                                                   \
        if ((v) != NULL) {                                                                         \
            memcpy((l)->data + (l)->count, (v), (c) * sizeof(*(l)->data));                         \
            (l)->count += (c);                                                                     \
        }                                                                                          \
    } while (0)

// Jumps
typedef struct {
    size_t *data;
    size_t count;
    size_t capacity;
} Jumps;

// Buffer
typedef struct {
    unsigned char *data;
    size_t count;
    size_t capacity;
} Buffer;

#define buffer_append(b, s) da_append_many(b, s, sizeof(s) - 1)

// Op
typedef enum {
    OP_ADD,
    OP_MOVE,
    OP_READ,
    OP_WRITE,
    OP_JUMP_IF,
    OP_JUMP_ELSE,
} OpType;

typedef struct {
    OpType type;
    int data;
} Op;

typedef struct {
    Op *data;
    size_t count;
    size_t capacity;
} Ops;

void ops_chain(Ops *ops, OpType type, long data) {
    if (ops->count > 0 && ops->data[ops->count - 1].type == type) {
        ops->data[ops->count - 1].data += data;
    } else {
        da_append(ops, ((Op){type, data}));
    }
}

int ops_parse(Ops *ops, const char *path) {
    int result = 1;
    Jumps jumps = {0};

    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Error: could not open file '%s'\n", path);
        return_defer(0);
    }

    while (!feof(f)) {
        switch (fgetc(f)) {
        case '+':
            ops_chain(ops, OP_ADD, 1);
            break;

        case '-':
            ops_chain(ops, OP_ADD, -1);
            break;

        case '>':
            ops_chain(ops, OP_MOVE, 1);
            break;

        case '<':
            ops_chain(ops, OP_MOVE, -1);
            break;

        case ',':
            da_append(ops, ((Op){OP_READ, 0}));
            break;

        case '.':
            da_append(ops, ((Op){OP_WRITE, 0}));
            break;

        case '[':
            da_append(&jumps, ops->count);
            da_append(ops, ((Op){OP_JUMP_ELSE, 0}));
            break;

        case ']':
            if (jumps.count == 0) {
                fprintf(stderr, "Error: unexpected ']'\n");
                return_defer(0);
            } else {
                size_t jump = jumps.data[--jumps.count];
                da_append(ops, ((Op){OP_JUMP_IF, jump + 1}));
                ops->data[jump].data = ops->count;
            }
            break;
        }
    }

    if (jumps.count != 0) {
        fprintf(stderr, "Error: unterminated '['\n");
        return_defer(0);
    }

defer:
    if (f) {
        fclose(f);
    }

    free(jumps.data);
    return result;
}

int ops_run(Ops ops, size_t size) {
    int result = 1;

    size_t ip = 0;
    size_t mp = 0;
    char *memory = malloc(size);

    while (ip < ops.count) {
        Op op = ops.data[ip++];

        switch (op.type) {
        case OP_ADD:
            memory[mp] += op.data;
            break;

        case OP_MOVE:
            mp += op.data;
            if (mp >= size) {
                fprintf(stderr, "Error: invalid memory pointer\n");
                return_defer(0);
            }
            break;

        case OP_READ:
            memory[mp] = fgetc(stdin);
            break;

        case OP_WRITE:
            fputc(memory[mp], stdout);
            break;

        case OP_JUMP_IF:
            if (memory[mp]) {
                ip = op.data;
            }
            break;

        case OP_JUMP_ELSE:
            if (!memory[mp]) {
                ip = op.data;
            }
            break;
        }
    }

defer:
    free(memory);
    return result;
}

int ops_jit(Ops ops, size_t size) {
    int result = 1;

    Jumps jumps = {0};

    Buffer buffer = {0};
    buffer_append(&buffer, "\x48\xc7\xc2\x01\x00\x00\x00\x48\x89\xfe");

    char *memory = NULL;
    void (*jit)(const char *) = MAP_FAILED;

    for (size_t i = 0; i < ops.count; i++) {
        Op op = ops.data[i];
        switch (op.type) {
        case OP_ADD:
            if (op.data != 0) {
                buffer_append(&buffer, "\x80\x06");
                da_append(&buffer, op.data % 256);
            }
            break;

        case OP_MOVE:
            if (op.data != 0) {
                buffer_append(&buffer, "\x48\x81\xc6");
                da_append_many(&buffer, &op.data, 4);
            }
            break;

        case OP_READ:
            buffer_append(&buffer,
                          "\x48\xc7\xc7\x00\x00\x00\x00\x48\xc7\xc0\x00\x00\x00\x00\x0f\x05");
            break;

        case OP_WRITE:
            buffer_append(&buffer,
                          "\x48\xc7\xc7\x01\x00\x00\x00\x48\xc7\xc0\x01\x00\x00\x00\x0f\x05");
            break;

        case OP_JUMP_IF: {
            int jump = jumps.data[--jumps.count];
            buffer_append(&buffer, "\x48\x31\xc0\x8a\x06\x48\x85\xc0");

            int a = jump - buffer.count;
            buffer_append(&buffer, "\x0f\x85");
            da_append_many(&buffer, &a, 4);

            int b = buffer.count - jump - 6;
            memcpy(&buffer.data[jump + 2], &b, 4);
        } break;

        case OP_JUMP_ELSE:
            buffer_append(&buffer, "\x48\x31\xc0\x8a\x06\x48\x85\xc0");
            da_append(&jumps, buffer.count);
            buffer_append(&buffer, "\x0f\x84\x00\x00\x00\x00");
            break;
        }
    }

    buffer_append(&buffer, "\xc3");

    jit = mmap(NULL, buffer.count, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
               -1, 0);

    if (jit == MAP_FAILED) {
        fprintf(stderr, "Error: could not allocate JIT function\n");
        return_defer(0);
    }

    memcpy(jit, buffer.data, buffer.count);

    memory = malloc(size);
    jit(memory);

defer:
    if (jit != MAP_FAILED) {
        munmap(jit, buffer.count);
    }

    free(memory);
    free(jumps.data);
    free(buffer.data);
    return result;
}

// Main
int main(int argc, char **argv) {
    int result = 0;

    if (argc < 2) {
        fprintf(stderr, "Error: file path not provided\n");
        fprintf(stderr, "Usage: %s <path>\n", *argv);
        return_defer(1);
    }

    Ops ops = {0};
    if (!ops_parse(&ops, argv[1])) {
        return_defer(1);
    }

#if BF_JIT
    if (!ops_jit(ops, BF_MEMORY)) {
        return_defer(1);
    }
#else
    if (!ops_run(ops, BF_MEMORY)) {
        return_defer(1);
    }
#endif

defer:
    free(ops.data);
    return result;
}
