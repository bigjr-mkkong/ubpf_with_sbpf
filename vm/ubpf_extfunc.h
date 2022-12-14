#ifndef __UBPF_EXTFUNC_H__
#define __UBPF_EXTFUNC_H__
#include "stdint.h"

extern uint64_t paratest(uint64_t val);
extern void ubpf_printl(const char *fmt, const uint64_t arg1, \
    const uint64_t arg2, const uint64_t arg3, const uint64_t arg4);

/*----------------------------------below are definition of vdso site updater/getter----------------------------------*/
extern uint64_t ubpf_sbvar_query(uint64_t in1, uint64_t in2);
extern void ubpf_sbvar_update(uint64_t in1, uint64_t in2, uint64_t len, uint64_t direction, uint64_t perc_sum);

#endif