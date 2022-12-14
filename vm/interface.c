#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <elf.h>
#include <math.h>
#include "ubpf.h"
#include <fcntl.h>

#include "ubpf_extfunc.h"

#include <time.h>
#include <sys/syscall.h>

static void *readfile(const char *path, size_t maxlen, size_t *len);
static void register_functions(struct ubpf_vm *vm);

int test_ubpf_load_elf(const char *code_path, const char *mem_path, double *time_comp, uint64_t *bpf_retval){
    size_t code_len;
    clock_t t_start, t_end;
    void *code=readfile(code_path, 1024*1024, &code_len);
    if (code==NULL) {
        return 1;
    }

    size_t mem_len;
    void *mem=NULL;
    if(mem_path!=NULL){
        mem=readfile(mem_path, 1024*1024, &mem_len);
        if(mem==NULL){
           return 1;
        }
    }

    struct ubpf_vm *vm=ubpf_create();
    if(!vm){
        return 1;
    }
    register_functions(vm);

    char *errmsg;
    /*
    if(syscall(__NR_SBPF_VERIFIER) != 0){
        fprintf(stderr,"Failed to verify this vm\n");
        ubpf_destroy(vm);
        return 1;
    }
    */
    int ret_val=ubpf_load_elf(vm, code, code_len, &errmsg);//parse elf
    free(code);

    if (ret_val<0) {
        fprintf(stderr, "Failed to load code: %s\n", errmsg);
        free(errmsg);
        ubpf_destroy(vm);
        return 1;
    }
    uint64_t ret;
    
    if (1) {    //jit
        ubpf_jit_fn fn = ubpf_compile(vm, &errmsg);
        if (fn == NULL) {
            fprintf(stderr, "Failed to compile: %s\n", errmsg);
            free(errmsg);
            free(mem);
            return 1;
        }
        t_start = clock();
        //*bpf_retval = fn(mem, mem_len);
        *bpf_retval = fn(mem, mem_len);
        
    } else {
        if (ubpf_exec(vm, mem, mem_len, &ret) < 0){
            ret = UINT64_MAX;
            fprintf(stderr, "Failed to execute, ");
        }
    }
    t_end = clock();
    *time_comp = (double)(t_end - t_start)/CLOCKS_PER_SEC*1000000;

    ubpf_destroy(vm);
    free(mem);
    return 0; 
}

static void *readfile(const char *path, size_t maxlen, size_t *len)
{
    FILE *file;
    if (!strcmp(path, "-")) {
        file = fdopen(STDIN_FILENO, "r");
    } else {
        file = fopen(path, "r");
    }

    if (file == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        return NULL;
    }

    void *data = calloc(maxlen, 1);
    size_t offset = 0;
    size_t rv;
    while ((rv = fread(data+offset, 1, maxlen-offset, file)) > 0) {
        offset += rv;
    }

    if (ferror(file)) {
        fprintf(stderr, "Failed to read %s: %s\n", path, strerror(errno));
        fclose(file);
        free(data);
        return NULL;
    }

    if (!feof(file)) {
        fprintf(stderr, "Failed to read %s because it is too large (max %u bytes)\n",
                path, (unsigned)maxlen);
        fclose(file);
        free(data);
        return NULL;
    }

    fclose(file);
    if (len) {
        *len = offset;
    }
    return data;
}

//#ifndef __GLIBC__
void *
memfrob(void *s, size_t n)
{
    for (int i = 0; i < n; i++) {
        ((char *)s)[i] ^= 42;
    }
    return s;
}
//#endif

static uint64_t
gather_bytes(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e)
{
    return ((uint64_t)a << 32) |
        ((uint32_t)b << 24) |
        ((uint32_t)c << 16) |
        ((uint16_t)d << 8) |
        e;
}

static void
trash_registers(void)
{
    /* Overwrite all caller-save registers */
#if __x86_64__
    asm(
        "mov $0xf0, %rax;"
        "mov $0xf1, %rcx;"
        "mov $0xf2, %rdx;"
        "mov $0xf3, %rsi;"
        "mov $0xf4, %rdi;"
        "mov $0xf5, %r8;"
        "mov $0xf6, %r9;"
        "mov $0xf7, %r10;"
        "mov $0xf8, %r11;"
    );
#elif __aarch64__
    asm(
        "mov w0, #0xf0;"
        "mov w1, #0xf1;"
        "mov w2, #0xf2;"
        "mov w3, #0xf3;"
        "mov w4, #0xf4;"
        "mov w5, #0xf5;"
        "mov w6, #0xf6;"
        "mov w7, #0xf7;"
        "mov w8, #0xf8;"
        "mov w9, #0xf9;"
        "mov w10, #0xfa;"
        "mov w11, #0xfb;"
        "mov w12, #0xfc;"
        "mov w13, #0xfd;"
        "mov w14, #0xfe;"
        "mov w15, #0xff;"
        ::: "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8", "w9", "w10", "w11", "w12", "w13", "w14", "w15"
    );
#else
    fprintf(stderr, "trash_registers not implemented for this architecture.\n");
    exit(1);
#endif
}

static uint64_t
unwind(uint64_t i)
{
    return i;
}

static void
register_functions(struct ubpf_vm *vm)
{
    ubpf_register(vm, 0, "gather_bytes", gather_bytes);
    ubpf_register(vm, 1, "memfrob", memfrob);
    ubpf_register(vm, 2, "trash_registers", trash_registers);
    //ubpf_register(vm, 3, "sqrti", sqrti);
    ubpf_register(vm, 4, "strcmp_ext", strcmp);
    ubpf_register(vm, 5, "unwind", unwind);
    
    ubpf_register(vm, 6, "paratest", paratest);
    ubpf_register(vm, 7, "ubpf_printl",ubpf_printl);
    ubpf_register(vm, 8, "ubpf_sbvar_query", ubpf_sbvar_query);
    ubpf_register(vm, 9, "ubpf_sbvar_update", ubpf_sbvar_update);
    
    ubpf_set_unwind_function_index(vm, 10);
}