#include "stdio.h"
#include "stdint.h"
#include "stdarg.h"
#include "string.h"
#include "errno.h"

#define MAX_PRINTF_LENGTH 4095

extern long sbpf_get_PSS_features(void);
extern long sbpf_set_PSS_features(uint64_t PSS_features);

extern int __vdso_query(int *input, int len);
extern int __vdso_update(int in1, int in2, int len, int direction, int perc_sum);

uint64_t paratest(uint64_t val){
    printf("Passed parameter: %ld\n",val);
    return val;
}
void ubpf_printl(const char *fmt, const uint64_t arg1, \
    const uint64_t arg2, const uint64_t arg3, const uint64_t arg4){
    fprintf(stdout,"[ubpf_printf] ");
    if (fprintf(stdout,fmt, arg1, arg2, arg3, arg4) < 0)
        fprintf(stderr, "Failed to print\n");
    fprintf(stdout,"\n");
    return;
}

/*----------------------------------below are vdso site updater/getter----------------------------------*/

uint64_t ubpf_sbvar_query(uint64_t in1, uint64_t in2){
    int args[2] = {(uint32_t)in1, (uint32_t)in2};
    return (uint64_t)__vdso_query(args, 2);
}

void ubpf_sbvar_update(uint64_t in1, uint64_t in2, uint64_t len, uint64_t direction, uint64_t perc_sum){
    __vdso_update(in1, in2, len, direction, perc_sum);
    return;
}