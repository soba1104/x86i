// 置き場に困ったグローバル変数を集めたファイル

#define NEED_CPU_REG_SHORTCUTS 1

#include "config.h"
#undef BX_SUPPORT_AVX // FIXME
#undef BX_SUPPORT_EVEX // FIXME
#define BX_CPP_INLINE inline
#include <stdint.h>
#include <assert.h>

#include "bochs.h"
#include "cpu.h"

bx_address bx_asize_mask[] = {
  0xffff,                         // as16 (asize = '00)
  0xffffffff,                     // as32 (asize = '01)
#if BX_SUPPORT_X86_64
  BX_CONST64(0xffffffffffffffff), // as64 (asize = '10)
  BX_CONST64(0xffffffffffffffff)  // as64 (asize = '11)
#endif
};
