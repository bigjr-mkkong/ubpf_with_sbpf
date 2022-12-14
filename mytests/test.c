#include "stdint.h"

#define u64      uint64_t

#define BATCH_TEST
//#define LOOP_TEST
//#define PRINT_TEST


int bpf_prog(void *mem, u64 mem_len){
    u64 ret_val=100;
#ifdef LOOP_TEST
    for(int i=0; i<100000; i++){
        __asm__ __volatile__(
            "r1 = %1    \n\t"
            "r2 = %2    \n\t"
            "r3 = %3    \n\t"
            "r4 = %4    \n\t"
            "r5 = %5    \n\t"
            "call 9    \n\t"
            "%0 = r0    \n\t"
            :"=r"(ret_val)
            :"r"(0),"r"(1),"r"(2),"r"(1),"r"(0)
            :"r1","r2","r3","r4","r5"
        );
    }
#endif

#ifdef BATCH_TEST

    u64 batch_cnt = 0, loops_per_update = *((u64*)mem);

    for(int i=0; i<100000; i++){
      batch_cnt++;
      if(loops_per_update == batch_cnt){
        __asm__ __volatile__(
            "r1 = %1    \n\t"
            "r2 = %2    \n\t"
            "r3 = %3    \n\t"
            "r4 = %4    \n\t"
            "r5 = %5    \n\t"
            "call 9    \n\t"
            "%0 = r0    \n\t"
            :"=r"(ret_val)
            :"r"(0),"r"(1),"r"(2),"r"(1),"r"(0)
            :"r1","r2","r3","r4","r5"
        );
        batch_cnt = 0;
      }
    }

#endif

#ifdef PRINT_TEST

  char fmtstr[] = "%s\n";
  char *str = (char*)mem;
  __asm__ __volatile__(
    "r1 = %1    \n\t"
    "r2 = %0    \n\t"
    "call 7     \n\t"
    :
    :"r"(str),"r"(fmtstr)
    :"r1","r2","r0"
  );

#endif
    return ret_val;
}