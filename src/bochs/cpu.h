/////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2015 satoshi shiba
// Copyright (C) 2001-2015  The Bochs Project
//
// Original source of this file is 'cpu/cpu.h'.
// You can download original source from following link.
// http://sourceforge.net/projects/bochs/files/bochs/2.6.8/
//  -------------------------- Original Copyright ------------------------------
// |////////////////////////////////////////////////////////////////////////////|
// |// $Id: cpu.h 12793 2015-07-13 20:24:14Z sshwarts $                         |
// |////////////////////////////////////////////////////////////////////////////|
// |                                                                            |
// | Copyright (C) 2001-2015  The Bochs Project                                 |
// |                                                                            |
// | This library is free software; you can redistribute it and/or              |
// | modify it under the terms of the GNU Lesser General Public                 |
// | License as published by the Free Software Foundation; either               |
// | version 2 of the License, or (at your option) any later version.           |
// |                                                                            |
// | This library is distributed in the hope that it will be useful,            |
// | but WITHOUT ANY WARRANTY; without even the implied warranty of             |
// | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU          |
// | Lesser General Public License for more details.                            |
// |                                                                            |
// | You should have received a copy of the GNU Lesser General Public           |
// | License along with this library; if not, write to the Free Software        |
// | Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA B 02110-1301 USA |
//  ----------------------------------------------------------------------------
/////////////////////////////////////////////////////////////////////////////////

#ifndef BX_CPU_H
#  define BX_CPU_H 1

#include <setjmp.h>

// <TAG-DEFINES-DECODE-START>
// segment register encoding
enum {
  BX_SEG_REG_ES = 0,
  BX_SEG_REG_CS = 1,
  BX_SEG_REG_SS = 2,
  BX_SEG_REG_DS = 3,
  BX_SEG_REG_FS = 4,
  BX_SEG_REG_GS = 5,
  // NULL now has to fit in 3 bits.
  BX_SEG_REG_NULL = 7
};

#define BX_NULL_SEG_REG(seg) ((seg) == BX_SEG_REG_NULL)

enum {
  BX_16BIT_REG_AX,
  BX_16BIT_REG_CX,
  BX_16BIT_REG_DX,
  BX_16BIT_REG_BX,
  BX_16BIT_REG_SP,
  BX_16BIT_REG_BP,
  BX_16BIT_REG_SI,
  BX_16BIT_REG_DI
};

enum {
  BX_32BIT_REG_EAX,
  BX_32BIT_REG_ECX,
  BX_32BIT_REG_EDX,
  BX_32BIT_REG_EBX,
  BX_32BIT_REG_ESP,
  BX_32BIT_REG_EBP,
  BX_32BIT_REG_ESI,
  BX_32BIT_REG_EDI
};

enum {
  BX_64BIT_REG_RAX,
  BX_64BIT_REG_RCX,
  BX_64BIT_REG_RDX,
  BX_64BIT_REG_RBX,
  BX_64BIT_REG_RSP,
  BX_64BIT_REG_RBP,
  BX_64BIT_REG_RSI,
  BX_64BIT_REG_RDI,
  BX_64BIT_REG_R8,
  BX_64BIT_REG_R9,
  BX_64BIT_REG_R10,
  BX_64BIT_REG_R11,
  BX_64BIT_REG_R12,
  BX_64BIT_REG_R13,
  BX_64BIT_REG_R14,
  BX_64BIT_REG_R15
};

#if BX_SUPPORT_X86_64
# define BX_GENERAL_REGISTERS 16
#else
# define BX_GENERAL_REGISTERS 8
#endif

#define BX_16BIT_REG_IP  (BX_GENERAL_REGISTERS)
#define BX_32BIT_REG_EIP (BX_GENERAL_REGISTERS)
#define BX_64BIT_REG_RIP (BX_GENERAL_REGISTERS)

#define BX_TMP_REGISTER  (BX_GENERAL_REGISTERS+1)
#define BX_NIL_REGISTER  (BX_GENERAL_REGISTERS+2)
// <TAG-DEFINES-DECODE-END>

#if defined(NEED_CPU_REG_SHORTCUTS)

/* WARNING:
   Only BX_CPU_C member functions can use these shortcuts safely!
   Functions that use the shortcuts outside of BX_CPU_C might work
   when BX_USE_CPU_SMF=1 but will fail when BX_USE_CPU_SMF=0
   (for example in SMP mode).
*/

// access to 8 bit general registers
#define AL (BX_CPU_THIS_PTR gen_reg[0].word.byte.rl)
#define CL (BX_CPU_THIS_PTR gen_reg[1].word.byte.rl)
#define DL (BX_CPU_THIS_PTR gen_reg[2].word.byte.rl)
#define BL (BX_CPU_THIS_PTR gen_reg[3].word.byte.rl)
#define AH (BX_CPU_THIS_PTR gen_reg[0].word.byte.rh)
#define CH (BX_CPU_THIS_PTR gen_reg[1].word.byte.rh)
#define DH (BX_CPU_THIS_PTR gen_reg[2].word.byte.rh)
#define BH (BX_CPU_THIS_PTR gen_reg[3].word.byte.rh)

#define TMP8L (BX_CPU_THIS_PTR gen_reg[BX_TMP_REGISTER].word.byte.rl)

// access to 16 bit general registers
#define AX (BX_CPU_THIS_PTR gen_reg[0].word.rx)
#define CX (BX_CPU_THIS_PTR gen_reg[1].word.rx)
#define DX (BX_CPU_THIS_PTR gen_reg[2].word.rx)
#define BX (BX_CPU_THIS_PTR gen_reg[3].word.rx)
#define SP (BX_CPU_THIS_PTR gen_reg[4].word.rx)
#define BP (BX_CPU_THIS_PTR gen_reg[5].word.rx)
#define SI (BX_CPU_THIS_PTR gen_reg[6].word.rx)
#define DI (BX_CPU_THIS_PTR gen_reg[7].word.rx)

// access to 16 bit instruction pointer
#define IP (BX_CPU_THIS_PTR gen_reg[BX_16BIT_REG_IP].word.rx)

#define TMP16 (BX_CPU_THIS_PTR gen_reg[BX_TMP_REGISTER].word.rx)

// accesss to 32 bit general registers
#define EAX (BX_CPU_THIS_PTR gen_reg[0].dword.erx)
#define ECX (BX_CPU_THIS_PTR gen_reg[1].dword.erx)
#define EDX (BX_CPU_THIS_PTR gen_reg[2].dword.erx)
#define EBX (BX_CPU_THIS_PTR gen_reg[3].dword.erx)
#define ESP (BX_CPU_THIS_PTR gen_reg[4].dword.erx)
#define EBP (BX_CPU_THIS_PTR gen_reg[5].dword.erx)
#define ESI (BX_CPU_THIS_PTR gen_reg[6].dword.erx)
#define EDI (BX_CPU_THIS_PTR gen_reg[7].dword.erx)

// access to 32 bit instruction pointer
#define EIP (BX_CPU_THIS_PTR gen_reg[BX_32BIT_REG_EIP].dword.erx)

#define TMP32 (BX_CPU_THIS_PTR gen_reg[BX_TMP_REGISTER].dword.erx)

#if BX_SUPPORT_X86_64

// accesss to 64 bit general registers
#define RAX (BX_CPU_THIS_PTR gen_reg[0].rrx)
#define RCX (BX_CPU_THIS_PTR gen_reg[1].rrx)
#define RDX (BX_CPU_THIS_PTR gen_reg[2].rrx)
#define RBX (BX_CPU_THIS_PTR gen_reg[3].rrx)
#define RSP (BX_CPU_THIS_PTR gen_reg[4].rrx)
#define RBP (BX_CPU_THIS_PTR gen_reg[5].rrx)
#define RSI (BX_CPU_THIS_PTR gen_reg[6].rrx)
#define RDI (BX_CPU_THIS_PTR gen_reg[7].rrx)
#define R8  (BX_CPU_THIS_PTR gen_reg[8].rrx)
#define R9  (BX_CPU_THIS_PTR gen_reg[9].rrx)
#define R10 (BX_CPU_THIS_PTR gen_reg[10].rrx)
#define R11 (BX_CPU_THIS_PTR gen_reg[11].rrx)
#define R12 (BX_CPU_THIS_PTR gen_reg[12].rrx)
#define R13 (BX_CPU_THIS_PTR gen_reg[13].rrx)
#define R14 (BX_CPU_THIS_PTR gen_reg[14].rrx)
#define R15 (BX_CPU_THIS_PTR gen_reg[15].rrx)

// access to 64 bit instruction pointer
#define RIP (BX_CPU_THIS_PTR gen_reg[BX_64BIT_REG_RIP].rrx)

#define TMP64 (BX_CPU_THIS_PTR gen_reg[BX_TMP_REGISTER].rrx)

// access to 64 bit MSR registers
#define MSR_FSBASE  (BX_CPU_THIS_PTR sregs[BX_SEG_REG_FS].cache.u.segment.base)
#define MSR_GSBASE  (BX_CPU_THIS_PTR sregs[BX_SEG_REG_GS].cache.u.segment.base)

#else // simplify merge between 32-bit and 64-bit mode

#define RAX EAX
#define RCX ECX
#define RDX EDX
#define RBX EBX
#define RSP ESP
#define RBP EBP
#define RSI ESI
#define RDI EDI
#define RIP EIP

#endif // BX_SUPPORT_X86_64 == 0

#define PREV_RIP (BX_CPU_THIS_PTR prev_rip)

#if BX_SUPPORT_X86_64
#define BX_READ_8BIT_REGx(index,extended)  ((((index) & 4) == 0 || (extended)) ? \
  (BX_CPU_THIS_PTR gen_reg[index].word.byte.rl) : \
  (BX_CPU_THIS_PTR gen_reg[(index)-4].word.byte.rh))
#define BX_READ_64BIT_REG(index) (BX_CPU_THIS_PTR gen_reg[index].rrx)
#define BX_READ_64BIT_REG_HIGH(index) (BX_CPU_THIS_PTR gen_reg[index].dword.hrx)
#else
#define BX_READ_8BIT_REG(index)  (((index) & 4) ? \
  (BX_CPU_THIS_PTR gen_reg[(index)-4].word.byte.rh) : \
  (BX_CPU_THIS_PTR gen_reg[index].word.byte.rl))
#define BX_READ_8BIT_REGx(index,ext) BX_READ_8BIT_REG(index)
#endif

#define BX_READ_8BIT_REGL(index) (BX_CPU_THIS_PTR gen_reg[index].word.byte.rl)
#define BX_READ_16BIT_REG(index) (BX_CPU_THIS_PTR gen_reg[index].word.rx)
#define BX_READ_32BIT_REG(index) (BX_CPU_THIS_PTR gen_reg[index].dword.erx)

#define BX_WRITE_8BIT_REGH(index, val) {\
  BX_CPU_THIS_PTR gen_reg[index].word.byte.rh = val; \
}

#define BX_WRITE_16BIT_REG(index, val) {\
  BX_CPU_THIS_PTR gen_reg[index].word.rx = val; \
}

/*
#define BX_WRITE_32BIT_REG(index, val) {\
  BX_CPU_THIS_PTR gen_reg[index].dword.erx = val; \
}
*/

#if BX_SUPPORT_X86_64

#define BX_WRITE_8BIT_REGx(index, extended, val) {\
  if (((index) & 4) == 0 || (extended)) \
    BX_CPU_THIS_PTR gen_reg[index].word.byte.rl = val; \
  else \
    BX_CPU_THIS_PTR gen_reg[(index)-4].word.byte.rh = val; \
}

#define BX_WRITE_32BIT_REGZ(index, val) {\
  BX_CPU_THIS_PTR gen_reg[index].rrx = (Bit32u) val; \
}

#define BX_WRITE_64BIT_REG(index, val) {\
  BX_CPU_THIS_PTR gen_reg[index].rrx = val; \
}
#define BX_CLEAR_64BIT_HIGH(index) {\
  BX_CPU_THIS_PTR gen_reg[index].dword.hrx = 0; \
}

#else

#define BX_WRITE_8BIT_REG(index, val) {\
  if ((index) & 4) \
    BX_CPU_THIS_PTR gen_reg[(index)-4].word.byte.rh = val; \
  else \
    BX_CPU_THIS_PTR gen_reg[index].word.byte.rl = val; \
}
#define BX_WRITE_8BIT_REGx(index, ext, val) BX_WRITE_8BIT_REG(index, val)

// For x86-32, I just pretend this one is like the macro above,
// so common code can be used.
#define BX_WRITE_32BIT_REGZ(index, val) {\
  BX_CPU_THIS_PTR gen_reg[index].dword.erx = (Bit32u) val; \
}

#define BX_CLEAR_64BIT_HIGH(index)

#endif

#define CPL       (BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].selector.rpl)

#define USER_PL   (BX_CPU_THIS_PTR user_pl) /* CPL == 3 */

#if BX_SUPPORT_SMP
#define BX_CPU_ID (BX_CPU_THIS_PTR bx_cpuid)
#else
#define BX_CPU_ID (0)
#endif

#if BX_SUPPORT_AVX

#define BX_READ_8BIT_OPMASK(index)  (BX_CPU_THIS_PTR opmask[index].word.byte.rl)
#define BX_READ_16BIT_OPMASK(index) (BX_CPU_THIS_PTR opmask[index].word.rx)
#define BX_READ_32BIT_OPMASK(index) (BX_CPU_THIS_PTR opmask[index].dword.erx)
#define BX_READ_OPMASK(index)       (BX_CPU_THIS_PTR opmask[index].rrx)

#define BX_SCALAR_ELEMENT_MASK(index) (BX_READ_32BIT_OPMASK(index) & 0x1)

#define BX_WRITE_OPMASK(index, val_64) { \
  BX_CPU_THIS_PTR opmask[index].rrx = val_64; \
}

#endif

#endif  // defined(NEED_CPU_REG_SHORTCUTS)

// <TAG-INSTRUMENTATION_COMMON-BEGIN>

// possible types passed to BX_INSTR_TLB_CNTRL()
enum {
  BX_INSTR_MOV_CR0 = 10,
  BX_INSTR_MOV_CR3 = 11,
  BX_INSTR_MOV_CR4 = 12,
  BX_INSTR_TASK_SWITCH = 13,
  BX_INSTR_CONTEXT_SWITCH = 14,
  BX_INSTR_INVLPG = 15,
  BX_INSTR_INVEPT = 16,
  BX_INSTR_INVVPID = 17,
  BX_INSTR_INVPCID = 18
};

// possible types passed to BX_INSTR_CACHE_CNTRL()
enum {
  BX_INSTR_INVD = 10,
  BX_INSTR_WBINVD = 11
};

// possible types passed to BX_INSTR_FAR_BRANCH() and BX_INSTR_UCNEAR_BRANCH()
enum {
  BX_INSTR_IS_JMP = 10,
  BX_INSTR_IS_JMP_INDIRECT = 11,
  BX_INSTR_IS_CALL = 12,
  BX_INSTR_IS_CALL_INDIRECT = 13,
  BX_INSTR_IS_RET = 14,
  BX_INSTR_IS_IRET = 15,
  BX_INSTR_IS_INT = 16,
  BX_INSTR_IS_SYSCALL = 17,
  BX_INSTR_IS_SYSRET = 18,
  BX_INSTR_IS_SYSENTER = 19,
  BX_INSTR_IS_SYSEXIT = 20
};

// possible types passed to BX_INSTR_PREFETCH_HINT()
enum {
  BX_INSTR_PREFETCH_NTA = 0,
  BX_INSTR_PREFETCH_T0  = 1,
  BX_INSTR_PREFETCH_T1  = 2,
  BX_INSTR_PREFETCH_T2  = 3
};

// <TAG-INSTRUMENTATION_COMMON-END>

// passed to internal debugger together with BX_READ/BX_WRITE/BX_EXECUTE/BX_RW
enum {
  BX_PDPTR0_ACCESS = 1,
  BX_PDPTR1_ACCESS,
  BX_PDPTR2_ACCESS,
  BX_PDPTR3_ACCESS,
  BX_PTE_ACCESS,
  BX_PDE_ACCESS,
  BX_PDTE_ACCESS,
  BX_PML4E_ACCESS,
  BX_EPT_PTE_ACCESS,
  BX_EPT_PDE_ACCESS,
  BX_EPT_PDTE_ACCESS,
  BX_EPT_PML4E_ACCESS,
  BX_VMCS_ACCESS,
  BX_SHADOW_VMCS_ACCESS,
  BX_MSR_BITMAP_ACCESS,
  BX_IO_BITMAP_ACCESS,
  BX_VMREAD_BITMAP_ACCESS,
  BX_VMWRITE_BITMAP_ACCESS,
  BX_VMX_LOAD_MSR_ACCESS,
  BX_VMX_STORE_MSR_ACCESS,
  BX_VMX_VAPIC_ACCESS,
  BX_VMX_PML_WRITE,
  BX_SMRAM_ACCESS
};

struct BxExceptionInfo {
  unsigned exception_type;
  unsigned exception_class;
  bx_bool push_error;
};

enum {
  BX_DE_EXCEPTION =  0, // Divide Error (fault)
  BX_DB_EXCEPTION =  1, // Debug (fault/trap)
  BX_BP_EXCEPTION =  3, // Breakpoint (trap)
  BX_OF_EXCEPTION =  4, // Overflow (trap)
  BX_BR_EXCEPTION =  5, // BOUND (fault)
  BX_UD_EXCEPTION =  6,
  BX_NM_EXCEPTION =  7,
  BX_DF_EXCEPTION =  8,
  BX_TS_EXCEPTION = 10,
  BX_NP_EXCEPTION = 11,
  BX_SS_EXCEPTION = 12,
  BX_GP_EXCEPTION = 13,
  BX_PF_EXCEPTION = 14,
  BX_MF_EXCEPTION = 16,
  BX_AC_EXCEPTION = 17,
  BX_MC_EXCEPTION = 18,
  BX_XM_EXCEPTION = 19,
  BX_VE_EXCEPTION = 20
};

const unsigned BX_CPU_HANDLED_EXCEPTIONS = 32;

/* MSR registers */
#define BX_MSR_TSC                 0x010
#define BX_MSR_APICBASE            0x01b
#define BX_MSR_TSC_ADJUST          0x03b

#if BX_CPU_LEVEL >= 6
  #define BX_MSR_SYSENTER_CS       0x174
  #define BX_MSR_SYSENTER_ESP      0x175
  #define BX_MSR_SYSENTER_EIP      0x176
#endif

#define BX_MSR_DEBUGCTLMSR         0x1d9
#define BX_MSR_LASTBRANCHFROMIP    0x1db
#define BX_MSR_LASTBRANCHTOIP      0x1dc
#define BX_MSR_LASTINTOIP          0x1dd

const unsigned BX_NUM_VARIABLE_RANGE_MTRRS = 8;

#if BX_CPU_LEVEL >= 6
  #define BX_MSR_MTRRCAP           0x0fe
  #define BX_MSR_MTRRPHYSBASE0     0x200
  #define BX_MSR_MTRRPHYSMASK0     0x201
  #define BX_MSR_MTRRPHYSBASE1     0x202
  #define BX_MSR_MTRRPHYSMASK1     0x203
  #define BX_MSR_MTRRPHYSBASE2     0x204
  #define BX_MSR_MTRRPHYSMASK2     0x205
  #define BX_MSR_MTRRPHYSBASE3     0x206
  #define BX_MSR_MTRRPHYSMASK3     0x207
  #define BX_MSR_MTRRPHYSBASE4     0x208
  #define BX_MSR_MTRRPHYSMASK4     0x209
  #define BX_MSR_MTRRPHYSBASE5     0x20a
  #define BX_MSR_MTRRPHYSMASK5     0x20b
  #define BX_MSR_MTRRPHYSBASE6     0x20c
  #define BX_MSR_MTRRPHYSMASK6     0x20d
  #define BX_MSR_MTRRPHYSBASE7     0x20e
  #define BX_MSR_MTRRPHYSMASK7     0x20f
  #define BX_MSR_MTRRFIX64K_00000  0x250
  #define BX_MSR_MTRRFIX16K_80000  0x258
  #define BX_MSR_MTRRFIX16K_A0000  0x259
  #define BX_MSR_MTRRFIX4K_C0000   0x268
  #define BX_MSR_MTRRFIX4K_C8000   0x269
  #define BX_MSR_MTRRFIX4K_D0000   0x26a
  #define BX_MSR_MTRRFIX4K_D8000   0x26b
  #define BX_MSR_MTRRFIX4K_E0000   0x26c
  #define BX_MSR_MTRRFIX4K_E8000   0x26d
  #define BX_MSR_MTRRFIX4K_F0000   0x26e
  #define BX_MSR_MTRRFIX4K_F8000   0x26f
  #define BX_MSR_PAT               0x277
  #define BX_MSR_MTRR_DEFTYPE      0x2ff
#endif

#if BX_SUPPORT_PERFMON
  #define BX_MSR_PMC0              0x0c1  /* PERFCTR0 */
  #define BX_MSR_PMC1              0x0c2  /* PERFCTR1 */
  #define BX_MSR_PMC2              0x0c3
  #define BX_MSR_PMC3              0x0c4
  #define BX_MSR_PMC4              0x0c5
  #define BX_MSR_PMC5              0x0c6
  #define BX_MSR_PMC6              0x0c7
  #define BX_MSR_PMC7              0x0c8
  #define BX_MSR_PERFEVTSEL0       0x186
  #define BX_MSR_PERFEVTSEL1       0x187
  #define BX_MSR_PERFEVTSEL2       0x188
  #define BX_MSR_PERFEVTSEL3       0x189
  #define BX_MSR_PERFEVTSEL4       0x18a
  #define BX_MSR_PERFEVTSEL5       0x18b 
  #define BX_MSR_PERFEVTSEL6       0x18c
  #define BX_MSR_PERFEVTSEL7       0x18d
  #define BX_MSR_PERF_FIXED_CTR0   0x309  /* Fixed Performance Counter 0 (R/W): Counts Instr_Retired.Any */
  #define BX_MSR_PERF_FIXED_CTR1   0x30a  /* Fixed Performance Counter 1 (R/W): Counts CPU_CLK_Unhalted.Core */
  #define BX_MSR_PERF_FIXED_CTR2   0x30b  /* Fixed Performance Counter 2 (R/W): Counts CPU_CLK_Unhalted.Ref */
  #define BX_MSR_FIXED_CTR_CTRL    0x38d  /* Fixed Performance Counter Control (R/W) */
  #define BX_MSR_PERF_GLOBAL_CTRL  0x38f  /* Global Performance Counter Control */
#endif

#define BX_MSR_TSC_DEADLINE        0x6E0

#define BX_MSR_MAX_INDEX          0x1000

enum {
  BX_MEMTYPE_UC = 0,
  BX_MEMTYPE_WC = 1,
  BX_MEMTYPE_RESERVED2 = 2,
  BX_MEMTYPE_RESERVED3 = 3,
  BX_MEMTYPE_WT = 4,
  BX_MEMTYPE_WP = 5,
  BX_MEMTYPE_WB = 6,
  BX_MEMTYPE_UC_WEAK = 7, // PAT only
  BX_MEMTYPE_INVALID = 8
};

typedef unsigned BxMemtype;

// avoid wasting cycles to determine memory type if not required
#if BX_SUPPORT_MEMTYPE
  #define MEMTYPE(memtype) (memtype)
#else
  #define MEMTYPE(memtype) (BX_MEMTYPE_UC)
#endif

#if BX_SUPPORT_VMX
  #define BX_MSR_VMX_BASIC                0x480
  #define BX_MSR_VMX_PINBASED_CTRLS       0x481
  #define BX_MSR_VMX_PROCBASED_CTRLS      0x482
  #define BX_MSR_VMX_VMEXIT_CTRLS         0x483
  #define BX_MSR_VMX_VMENTRY_CTRLS        0x484
  #define BX_MSR_VMX_MISC                 0x485
  #define BX_MSR_VMX_CR0_FIXED0           0x486
  #define BX_MSR_VMX_CR0_FIXED1           0x487
  #define BX_MSR_VMX_CR4_FIXED0           0x488
  #define BX_MSR_VMX_CR4_FIXED1           0x489
  #define BX_MSR_VMX_VMCS_ENUM            0x48a
  #define BX_MSR_VMX_PROCBASED_CTRLS2     0x48b
  #define BX_MSR_VMX_EPT_VPID_CAP         0x48c
  #define BX_MSR_VMX_TRUE_PINBASED_CTRLS  0x48d
  #define BX_MSR_VMX_TRUE_PROCBASED_CTRLS 0x48e
  #define BX_MSR_VMX_TRUE_VMEXIT_CTRLS    0x48f
  #define BX_MSR_VMX_TRUE_VMENTRY_CTRLS   0x490
  #define BX_MSR_VMX_VMFUNC               0x491
  #define BX_MSR_IA32_FEATURE_CONTROL     0x03A
  #define BX_MSR_IA32_SMM_MONITOR_CTL     0x09B
#endif

#define BX_MSR_EFER             0xc0000080
#define BX_MSR_STAR             0xc0000081
#define BX_MSR_LSTAR            0xc0000082
#define BX_MSR_CSTAR            0xc0000083
#define BX_MSR_FMASK            0xc0000084
#define BX_MSR_FSBASE           0xc0000100
#define BX_MSR_GSBASE           0xc0000101
#define BX_MSR_KERNELGSBASE     0xc0000102
#define BX_MSR_TSC_AUX          0xc0000103

#define BX_SVM_VM_CR_MSR        0xc0010114
#define BX_SVM_IGNNE_MSR        0xc0010115
#define BX_SVM_SMM_CTL_MSR      0xc0010116
#define BX_SVM_HSAVE_PA_MSR     0xc0010117

enum BxCpuMode {
  BX_MODE_IA32_REAL = 0,        // CR0.PE=0                |
  BX_MODE_IA32_V8086 = 1,       // CR0.PE=1, EFLAGS.VM=1   | EFER.LMA=0
  BX_MODE_IA32_PROTECTED = 2,   // CR0.PE=1, EFLAGS.VM=0   |
  BX_MODE_LONG_COMPAT = 3,      // EFER.LMA = 1, CR0.PE=1, CS.L=0
  BX_MODE_LONG_64 = 4           // EFER.LMA = 1, CR0.PE=1, CS.L=1
};

extern const char* cpu_mode_string(unsigned cpu_mode);

#if BX_SUPPORT_X86_64
#define IsCanonical(offset) ((Bit64u)((((Bit64s)(offset)) >> (BX_LIN_ADDRESS_WIDTH-1)) + 1) < 2)
#endif

BX_CPP_INLINE bx_bool IsValidPhyAddr(bx_phy_address addr)
{
  return ((addr & BX_PHY_ADDRESS_RESERVED_BITS) == 0);
}

BX_CPP_INLINE bx_bool IsValidPageAlignedPhyAddr(bx_phy_address addr)
{
  return ((addr & (BX_PHY_ADDRESS_RESERVED_BITS | 0xfff)) == 0);
}

const Bit32u CACHE_LINE_SIZE = 64;

class BX_CPU_C;
class BX_MEM_C;

#if BX_USE_CPU_SMF == 0
// normal member functions.  This can ONLY be used within BX_CPU_C classes.
// Anyone on the outside should use the BX_CPU macro (defined in bochs.h)
// instead.
#  define BX_CPU_THIS_PTR  this->
#  define BX_CPU_THIS      this
#  define BX_SMF
// with normal member functions, calling a member fn pointer looks like
// object->*(fnptr)(arg, ...);
// Since this is different from when SMF=1, encapsulate it in a macro.
#  define BX_CPU_CALL_METHOD(func, args) \
            (this->*((BxExecutePtr_tR) (func))) args
#  define BX_CPU_CALL_REP_ITERATION(func, args) \
            (this->*((BxRepIterationPtr_tR) (func))) args
#else
// static member functions.  With SMF, there is only one CPU by definition.
#  define BX_CPU_THIS_PTR  BX_CPU(0)->
#  define BX_CPU_THIS      BX_CPU(0)
#  define BX_SMF           static
#  define BX_CPU_CALL_METHOD(func, args) \
            ((BxExecutePtr_tR) (func)) args
#  define BX_CPU_CALL_REP_ITERATION(func, args) \
            ((BxRepIterationPtr_tR) (func)) args
#endif

//
// BX_CPU_RESOLVE_ADDR:
// Resolve virtual address of the instruction's memory reference without any
// assumptions about instruction's operand size, address size or execution
// mode
//
// BX_CPU_RESOLVE_ADDR_64:
// Resolve virtual address of the instruction memory reference assuming
// the instruction is executed in 64-bit long mode with possible 64-bit
// or 32-bit address size.
//
// BX_CPU_RESOLVE_ADDR_32:
// Resolve virtual address of the instruction memory reference assuming
// the instruction is executed in legacy or compatibility mode with
// possible 32-bit or 16-bit address size.
//
//
#if BX_SUPPORT_X86_64
#  define BX_CPU_RESOLVE_ADDR(i) \
            ((i)->as64L() ? BxResolve64(i) : BxResolve32(i))
#  define BX_CPU_RESOLVE_ADDR_64(i) \
            ((i)->as64L() ? BxResolve64(i) : BxResolve32(i))
#else
#  define BX_CPU_RESOLVE_ADDR(i) \
            (BxResolve32(i))
#endif
#  define BX_CPU_RESOLVE_ADDR_32(i) \
            (BxResolve32(i))


#if BX_SUPPORT_SMP
// multiprocessor simulation, we need an array of cpus and memories
BOCHSAPI extern BX_CPU_C **bx_cpu_array;
#else
// single processor simulation, so there's one of everything
BOCHSAPI extern BX_CPU_C   bx_cpu;
#endif

// notify internal debugger/instrumentation about memory access
#define BX_NOTIFY_LIN_MEMORY_ACCESS(laddr, paddr, size, memtype, rw, dataptr) {              \
  BX_INSTR_LIN_ACCESS(BX_CPU_ID, (laddr), (paddr), (size), (memtype), (rw));                 \
  BX_DBG_LIN_MEMORY_ACCESS(BX_CPU_ID, (laddr), (paddr), (size), (memtype), (rw), (dataptr)); \
}

#define BX_NOTIFY_PHY_MEMORY_ACCESS(paddr, size, memtype, rw, why, dataptr) {              \
  BX_INSTR_PHY_ACCESS(BX_CPU_ID, (paddr), (size), (memtype), (rw));                        \
  BX_DBG_PHY_MEMORY_ACCESS(BX_CPU_ID, (paddr), (size), (memtype), (rw), (why), (dataptr)); \
}

// accessors for all eflags in bx_flags_reg_t
// The macro is used once for each flag bit
// Do not use for arithmetic flags !
#define DECLARE_EFLAG_ACCESSOR(name,bitnum)                     \
  BX_SMF BX_CPP_INLINE Bit32u  get_##name ();                   \
  BX_SMF BX_CPP_INLINE bx_bool getB_##name ();                  \
  BX_SMF BX_CPP_INLINE void assert_##name ();                   \
  BX_SMF BX_CPP_INLINE void clear_##name ();                    \
  BX_SMF BX_CPP_INLINE void set_##name (bx_bool val);

#define IMPLEMENT_EFLAG_ACCESSOR(name,bitnum)                   \
  BX_CPP_INLINE bx_bool BX_CPU_C::getB_##name () {              \
    return 1 & (BX_CPU_THIS_PTR eflags >> bitnum);              \
  }                                                             \
  BX_CPP_INLINE Bit32u  BX_CPU_C::get_##name () {               \
    return BX_CPU_THIS_PTR eflags & (1 << bitnum);              \
  }

#define IMPLEMENT_EFLAG_SET_ACCESSOR(name,bitnum)               \
  BX_CPP_INLINE void BX_CPU_C::assert_##name () {               \
    BX_CPU_THIS_PTR eflags |= (1<<bitnum);                      \
  }                                                             \
  BX_CPP_INLINE void BX_CPU_C::clear_##name () {                \
    BX_CPU_THIS_PTR eflags &= ~(1<<bitnum);                     \
  }                                                             \
  BX_CPP_INLINE void BX_CPU_C::set_##name (bx_bool val) {       \
    BX_CPU_THIS_PTR eflags =                                    \
      (BX_CPU_THIS_PTR eflags&~(1<<bitnum))|((val)<<bitnum);    \
  }

#if BX_CPU_LEVEL >= 4

#define IMPLEMENT_EFLAG_SET_ACCESSOR_AC(bitnum)                 \
  BX_CPP_INLINE void BX_CPU_C::assert_AC() {                    \
    BX_CPU_THIS_PTR eflags |= (1<<bitnum);                      \
    handleAlignmentCheck();                                     \
  }                                                             \
  BX_CPP_INLINE void BX_CPU_C::clear_AC() {                     \
    BX_CPU_THIS_PTR eflags &= ~(1<<bitnum);                     \
    handleAlignmentCheck();                                     \
  }                                                             \
  BX_CPP_INLINE void BX_CPU_C::set_AC(bx_bool val) {            \
    BX_CPU_THIS_PTR eflags =                                    \
      (BX_CPU_THIS_PTR eflags&~(1<<bitnum))|((val)<<bitnum);    \
    handleAlignmentCheck();                                     \
  }

#endif

#define IMPLEMENT_EFLAG_SET_ACCESSOR_VM(bitnum)                 \
  BX_CPP_INLINE void BX_CPU_C::assert_VM() {                    \
    set_VM(1);                                                  \
  }                                                             \
  BX_CPP_INLINE void BX_CPU_C::clear_VM() {                     \
    set_VM(0);                                                  \
  }                                                             \
  BX_CPP_INLINE void BX_CPU_C::set_VM(bx_bool val) {            \
    if (!long_mode()) {                                         \
      BX_CPU_THIS_PTR eflags =                                  \
        (BX_CPU_THIS_PTR eflags&~(1<<bitnum))|((val)<<bitnum);  \
      handleCpuModeChange();                                    \
    }                                                           \
  }

// need special handling when IF is set
#define IMPLEMENT_EFLAG_SET_ACCESSOR_IF(bitnum)                 \
  BX_CPP_INLINE void BX_CPU_C::assert_IF() {                    \
    BX_CPU_THIS_PTR eflags |= (1<<bitnum);                      \
    handleInterruptMaskChange();                                \
  }                                                             \
  BX_CPP_INLINE void BX_CPU_C::clear_IF() {                     \
    BX_CPU_THIS_PTR eflags &= ~(1<<bitnum);                     \
    handleInterruptMaskChange();                                \
  }                                                             \
  BX_CPP_INLINE void BX_CPU_C::set_IF(bx_bool val) {            \
    if (val) assert_IF();                                       \
    else clear_IF();                                            \
  }

// assert async_event when TF is set
#define IMPLEMENT_EFLAG_SET_ACCESSOR_TF(bitnum)                 \
  BX_CPP_INLINE void BX_CPU_C::assert_TF() {                    \
    BX_CPU_THIS_PTR async_event = 1;                            \
    BX_CPU_THIS_PTR eflags |= (1<<bitnum);                      \
  }                                                             \
  BX_CPP_INLINE void BX_CPU_C::clear_TF() {                     \
    BX_CPU_THIS_PTR eflags &= ~(1<<bitnum);                     \
  }                                                             \
  BX_CPP_INLINE void BX_CPU_C::set_TF(bx_bool val) {            \
    if (val) BX_CPU_THIS_PTR async_event = 1;                   \
    BX_CPU_THIS_PTR eflags =                                    \
      (BX_CPU_THIS_PTR eflags&~(1<<bitnum))|((val)<<bitnum);    \
  }

// invalidate prefetch queue and call prefetch() when RF is set
#define IMPLEMENT_EFLAG_SET_ACCESSOR_RF(bitnum)                 \
  BX_CPP_INLINE void BX_CPU_C::assert_RF() {                    \
    invalidate_prefetch_q();                                    \
    BX_CPU_THIS_PTR eflags |= (1<<bitnum);                      \
  }                                                             \
  BX_CPP_INLINE void BX_CPU_C::clear_RF() {                     \
    BX_CPU_THIS_PTR eflags &= ~(1<<bitnum);                     \
  }                                                             \
  BX_CPP_INLINE void BX_CPU_C::set_RF(bx_bool val) {            \
    if (val) invalidate_prefetch_q();                           \
    BX_CPU_THIS_PTR eflags =                                    \
      (BX_CPU_THIS_PTR eflags&~(1<<bitnum))|((val)<<bitnum);    \
  }

#define DECLARE_EFLAG_ACCESSOR_IOPL(bitnum)                     \
  BX_SMF BX_CPP_INLINE void set_IOPL(Bit32u val);               \
  BX_SMF BX_CPP_INLINE Bit32u  get_IOPL(void);                  

#define IMPLEMENT_EFLAG_ACCESSOR_IOPL(bitnum)                   \
  BX_CPP_INLINE void BX_CPU_C::set_IOPL(Bit32u val) {           \
    BX_CPU_THIS_PTR eflags &= ~(3<<12);                         \
    BX_CPU_THIS_PTR eflags |= ((3&val) << 12);                  \
  }                                                             \
  BX_CPP_INLINE Bit32u BX_CPU_C::get_IOPL() {                   \
    return 3 & (BX_CPU_THIS_PTR eflags >> 12);                  \
  }

const Bit32u EFlagsCFMask   = (1 <<  0);
const Bit32u EFlagsPFMask   = (1 <<  2);
const Bit32u EFlagsAFMask   = (1 <<  4);
const Bit32u EFlagsZFMask   = (1 <<  6);
const Bit32u EFlagsSFMask   = (1 <<  7);
const Bit32u EFlagsTFMask   = (1 <<  8);
const Bit32u EFlagsIFMask   = (1 <<  9);
const Bit32u EFlagsDFMask   = (1 << 10);
const Bit32u EFlagsOFMask   = (1 << 11);
const Bit32u EFlagsIOPLMask = (3 << 12);
const Bit32u EFlagsNTMask   = (1 << 14);
const Bit32u EFlagsRFMask   = (1 << 16);
const Bit32u EFlagsVMMask   = (1 << 17);
const Bit32u EFlagsACMask   = (1 << 18);
const Bit32u EFlagsVIFMask  = (1 << 19);
const Bit32u EFlagsVIPMask  = (1 << 20);
const Bit32u EFlagsIDMask   = (1 << 21);

const Bit32u EFlagsOSZAPCMask = \
    (EFlagsCFMask | EFlagsPFMask | EFlagsAFMask | EFlagsZFMask | EFlagsSFMask | EFlagsOFMask);

const Bit32u EFlagsOSZAPMask = \
    (EFlagsPFMask | EFlagsAFMask | EFlagsZFMask | EFlagsSFMask | EFlagsOFMask);

const Bit32u EFlagsValidMask = 0x003f7fd5; // only supported bits for EFLAGS

#if BX_SUPPORT_FPU
#include "i387.h"
#endif

#if BX_CPU_LEVEL >= 5
typedef struct
{
#if BX_SUPPORT_APIC
  bx_phy_address apicbase;
#endif

  // SYSCALL/SYSRET instruction msr's
  Bit64u star;
#if BX_SUPPORT_X86_64
  Bit64u lstar;
  Bit64u cstar;
  Bit32u fmask;
  Bit64u kernelgsbase;
  Bit32u tsc_aux;
#endif

#if BX_CPU_LEVEL >= 6
  // SYSENTER/SYSEXIT instruction msr's
  Bit32u sysenter_cs_msr;
  bx_address sysenter_esp_msr;
  bx_address sysenter_eip_msr;

  BxPackedRegister pat;
  Bit64u mtrrphys[16];
  BxPackedRegister mtrrfix64k;
  BxPackedRegister mtrrfix16k[2];
  BxPackedRegister mtrrfix4k[8];
  Bit32u mtrr_deftype;
#endif

#if BX_SUPPORT_VMX
  Bit32u ia32_feature_ctrl;
#endif

#if BX_SUPPORT_SVM
  Bit64u svm_hsave_pa;
#endif

  /* TODO finish of the others */
} bx_regs_msr_t;
#endif

//#include "crregs.h"
//#include "descriptor.h"
#include "instr.h"
#include "lazy_flags.h"

// BX_TLB_SIZE: Number of entries in TLB
// BX_TLB_INDEX_OF(lpf): This macro is passed the linear page frame
//   (top 20 bits of the linear address.  It must map these bits to
//   one of the TLB cache slots, given the size of BX_TLB_SIZE.
//   There will be a many-to-one mapping to each TLB cache slot.
//   When there are collisions, the old entry is overwritten with
//   one for the newest access.

#define BX_TLB_SIZE 1024
#define BX_TLB_MASK ((BX_TLB_SIZE-1) << 12)
#define BX_TLB_INDEX_OF(lpf, len) ((((unsigned)(lpf) + (len)) & BX_TLB_MASK) >> 12)

typedef bx_ptr_equiv_t bx_hostpageaddr_t;

typedef struct {
  bx_address lpf;       // linear page frame
  bx_phy_address ppf;   // physical page frame
  bx_hostpageaddr_t hostPageAddr;
  Bit32u accessBits;
  Bit32u lpf_mask;      // linear address mask of the page size

#if BX_SUPPORT_MEMTYPE
  Bit32u memtype;      // keep it Bit32u for alignment
#endif

  Bit32u get_memtype() const {
#if BX_SUPPORT_MEMTYPE
    return memtype;
#else
    return BX_MEMTYPE_UC;
#endif
  }
} bx_TLB_entry;

#if BX_SUPPORT_X86_64
  #define LPF_MASK BX_CONST64(0xfffffffffffff000)
#else
  #define LPF_MASK (0xfffff000)
#endif

#if BX_PHY_ADDRESS_LONG
  #define PPF_MASK BX_CONST64(0xfffffffffffff000)
#else
  #define PPF_MASK (0xfffff000)
#endif

#define LPFOf(laddr)               ((laddr) & LPF_MASK)
#define PPFOf(laddr)               ((laddr) & PPF_MASK)

#define AlignedAccessLPFOf(laddr, alignment_mask) \
                  ((laddr) & (LPF_MASK | (alignment_mask)))

#define PAGE_OFFSET(laddr) ((Bit32u)(laddr) & 0xfff)

//#include "icache.h"

// general purpose register
#if BX_SUPPORT_X86_64

#ifdef BX_BIG_ENDIAN
typedef struct {
  union {
    struct {
      Bit32u dword_filler;
      Bit16u  word_filler;
      union {
        Bit16u rx;
        struct {
          Bit8u rh;
          Bit8u rl;
        } byte;
      };
    } word;
    Bit64u rrx;
    struct {
      Bit32u hrx;  // hi 32 bits
      Bit32u erx;  // lo 32 bits
    } dword;
  };
} bx_gen_reg_t;
#else
typedef struct {
  union {
    struct {
      union {
        Bit16u rx;
        struct {
          Bit8u rl;
          Bit8u rh;
        } byte;
      };
      Bit16u  word_filler;
      Bit32u dword_filler;
    } word;
    Bit64u rrx;
    struct {
      Bit32u erx;  // lo 32 bits
      Bit32u hrx;  // hi 32 bits
    } dword;
  };
} bx_gen_reg_t;

#endif

#else  // #if BX_SUPPORT_X86_64

#ifdef BX_BIG_ENDIAN
typedef struct {
  union {
    struct {
      Bit32u erx;
    } dword;
    struct {
      Bit16u word_filler;
      union {
        Bit16u rx;
        struct {
          Bit8u rh;
          Bit8u rl;
        } byte;
      };
    } word;
  };
} bx_gen_reg_t;
#else
typedef struct {
  union {
    struct {
      Bit32u erx;
    } dword;
    struct {
      union {
        Bit16u rx;
        struct {
          Bit8u rl;
          Bit8u rh;
        } byte;
      };
      Bit16u word_filler;
    } word;
  };
} bx_gen_reg_t;
#endif

#endif  // #if BX_SUPPORT_X86_64

#if BX_SUPPORT_APIC
//#include "apic.h"
#endif

#if BX_SUPPORT_FPU
#include "xmm.h"
#endif

#if BX_SUPPORT_VMX
#include "vmx.h"
#endif

#if BX_SUPPORT_SVM
#include "svm.h"
#endif

#if BX_SUPPORT_MONITOR_MWAIT
struct monitor_addr_t {

    bx_phy_address monitor_addr;
    bx_bool armed;

    monitor_addr_t(): monitor_addr(0xffffffff), armed(0) {}

    BX_CPP_INLINE void arm(bx_phy_address addr) {
      // align to cache line
      monitor_addr = addr & ~((bx_phy_address)(CACHE_LINE_SIZE - 1));
      armed = 1;
    }

    BX_CPP_INLINE void reset_monitor(void) { armed = 0; }
};
#endif

struct BX_SMM_State;
struct BxOpcodeInfo_t;
struct bx_cpu_statistics;

//#include "cpuid.h"

class BOCHSAPI BX_CPU_C {

public: // for now...
// <TAG-CLASS-CPU-START>
  // prototypes for CPU instructions...
  BX_SMF BX_INSF_TYPE PUSH16_Sw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE POP16_Sw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PUSH32_Sw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE POP32_Sw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE DAA(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE DAS(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AAA(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AAS(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AAM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AAD(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE PUSHA32(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PUSHA16(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE POPA32(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE POPA16(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ARPL_EwGw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PUSH_Id(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PUSH_Iw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF void INSB32_YbDX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void INSB16_YbDX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void INSW32_YwDX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void INSW16_YwDX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void INSD32_YdDX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void INSD16_YdDX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void OUTSB32_DXXb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void OUTSB16_DXXb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void OUTSW32_DXXw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void OUTSW16_DXXw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void OUTSD32_DXXd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void OUTSD16_DXXd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE REP_INSB_YbDX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE REP_INSW_YwDX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE REP_INSD_YdDX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE REP_OUTSB_DXXb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE REP_OUTSW_DXXw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE REP_OUTSD_DXXd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE BOUND_GwMa(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BOUND_GdMa(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE TEST_EbGbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE TEST_EwGwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE TEST_EdGdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE TEST_EbGbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE TEST_EwGwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE TEST_EdGdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE XCHG_EbGbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XCHG_EwGwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XCHG_EdGdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE XCHG_EbGbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XCHG_EwGwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XCHG_EdGdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE MOV_EbGbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_EwGwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_GbEbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_GbEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_GwEwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE MOV32_GdEdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV32_EdGdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE MOV32S_GdEdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV32S_EdGdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE MOV_EwSwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_EwSwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_SwEw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE LEA_GdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LEA_GwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE CBW(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CWD(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CALL32_Ap(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CALL16_Ap(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PUSHF_Fw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE POPF_Fw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PUSHF_Fd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE POPF_Fd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SAHF(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LAHF(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE MOV_ALOd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_EAXOd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_AXOd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_OdAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_OdEAX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_OdAX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  // repeatable instructions
  BX_SMF BX_INSF_TYPE REP_MOVSB_YbXb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE REP_MOVSW_YwXw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE REP_MOVSD_YdXd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE REP_CMPSB_XbYb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE REP_CMPSW_XwYw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE REP_CMPSD_XdYd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE REP_STOSB_YbAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE REP_LODSB_ALXb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE REP_SCASB_ALYb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE REP_STOSW_YwAX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE REP_LODSW_AXXw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE REP_SCASW_AXYw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE REP_STOSD_YdEAX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE REP_LODSD_EAXXd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE REP_SCASD_EAXYd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  // qualified by address size
  BX_SMF void CMPSB16_XbYb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void CMPSW16_XwYw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void CMPSD16_XdYd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void CMPSB32_XbYb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void CMPSW32_XwYw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void CMPSD32_XdYd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF void SCASB16_ALYb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void SCASW16_AXYw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void SCASD16_EAXYd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void SCASB32_ALYb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void SCASW32_AXYw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void SCASD32_EAXYd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF void LODSB16_ALXb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void LODSW16_AXXw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void LODSD16_EAXXd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void LODSB32_ALXb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void LODSW32_AXXw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void LODSD32_EAXXd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF void STOSB16_YbAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void STOSW16_YwAX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void STOSD16_YdEAX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void STOSB32_YbAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void STOSW32_YwAX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void STOSD32_YdEAX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF void MOVSB16_YbXb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void MOVSW16_YwXw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void MOVSD16_YdXd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void MOVSB32_YbXb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void MOVSW32_YwXw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void MOVSD32_YdXd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE MOV_EdIdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_EwIwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_EbIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ENTER16_IwIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ENTER32_IwIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LEAVE16(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LEAVE32(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE INT1(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE INT3(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE INT_Ib(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE INTO(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE IRET32(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE IRET16(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE SALC(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XLAT(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE LOOPNE16_Jb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LOOPE16_Jb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LOOP16_Jb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LOOPNE32_Jb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LOOPE32_Jb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LOOP32_Jb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JCXZ_Jb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JECXZ_Jb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE IN_ALIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE IN_AXIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE IN_EAXIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE OUT_IbAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE OUT_IbAX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE OUT_IbEAX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CALL_Jw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CALL_Jd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JMP_Jd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JMP_Jw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JMP_Ap(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE IN_ALDX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE IN_AXDX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE IN_EAXDX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE OUT_DXAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE OUT_DXAX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE OUT_DXEAX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE HLT(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMC(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CLC(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE STC(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CLI(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE STI(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CLD(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE STD(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE LAR_GvEw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LSL_GvEw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CLTS(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE INVD(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE WBINVD(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CLFLUSH(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE MOV_CR0Rd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_CR2Rd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_CR3Rd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_CR4Rd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_RdCR0(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_RdCR2(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_RdCR3(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_RdCR4(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_DdRd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_RdDd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE JO_Jw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JNO_Jw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JB_Jw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JNB_Jw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JZ_Jw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JNZ_Jw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JBE_Jw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JNBE_Jw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JS_Jw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JNS_Jw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JP_Jw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JNP_Jw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JL_Jw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JNL_Jw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JLE_Jw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JNLE_Jw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE JO_Jd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JNO_Jd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JB_Jd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JNB_Jd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JZ_Jd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JNZ_Jd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JBE_Jd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JNBE_Jd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JS_Jd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JNS_Jd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JP_Jd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JNP_Jd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JL_Jd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JNL_Jd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JLE_Jd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JNLE_Jd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE SETO_EbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETNO_EbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETB_EbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETNB_EbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETZ_EbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETNZ_EbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETBE_EbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETNBE_EbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETS_EbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETNS_EbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETP_EbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETNP_EbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETL_EbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETNL_EbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETLE_EbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETNLE_EbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE SETO_EbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETNO_EbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETB_EbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETNB_EbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETZ_EbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETNZ_EbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETBE_EbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETNBE_EbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETS_EbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETNS_EbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETP_EbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETNP_EbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETL_EbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETNL_EbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETLE_EbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SETNLE_EbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE CPUID(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE SHRD_EwGwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHRD_EwGwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHLD_EwGwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHLD_EwGwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHRD_EdGdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHRD_EdGdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHLD_EdGdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHLD_EdGdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE BSF_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BSF_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BSR_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BSR_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE BT_EwGwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BT_EdGdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTS_EwGwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTS_EdGdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTR_EwGwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTR_EdGdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTC_EwGwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTC_EdGdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE BT_EwGwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BT_EdGdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTS_EwGwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTS_EdGdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTR_EwGwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTR_EdGdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTC_EwGwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTC_EdGdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE BT_EwIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BT_EdIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTS_EwIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTS_EdIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTR_EwIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTR_EdIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTC_EwIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTC_EdIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE BT_EwIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BT_EdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTS_EwIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTS_EdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTR_EwIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTR_EdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTC_EwIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTC_EdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE LES_GwMp(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LDS_GwMp(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LSS_GwMp(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LFS_GwMp(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LGS_GwMp(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LES_GdMp(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LDS_GdMp(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LSS_GdMp(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LFS_GdMp(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LGS_GdMp(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE MOVZX_GwEbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVZX_GdEbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVZX_GdEwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVSX_GwEbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVSX_GdEbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVSX_GdEwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE MOVZX_GwEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVZX_GdEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVZX_GdEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVSX_GwEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVSX_GdEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVSX_GdEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE BSWAP_RX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BSWAP_ERX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ADD_GbEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE OR_GbEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADC_GbEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SBB_GbEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AND_GbEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SUB_GbEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XOR_GbEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMP_GbEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ADD_GbEbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE OR_GbEbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADC_GbEbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SBB_GbEbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AND_GbEbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SUB_GbEbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XOR_GbEbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMP_GbEbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ADD_EbIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE OR_EbIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADC_EbIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SBB_EbIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AND_EbIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SUB_EbIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XOR_EbIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMP_EbIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ADD_EbIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE OR_EbIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADC_EbIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SBB_EbIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AND_EbIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SUB_EbIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XOR_EbIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMP_EbIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ADD_EbGbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE OR_EbGbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADC_EbGbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SBB_EbGbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AND_EbGbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SUB_EbGbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XOR_EbGbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMP_EbGbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ADD_EwIwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE OR_EwIwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADC_EwIwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SBB_EwIwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AND_EwIwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SUB_EwIwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XOR_EwIwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMP_EwIwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ADD_EwIwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE OR_EwIwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADC_EwIwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SBB_EwIwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AND_EwIwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SUB_EwIwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XOR_EwIwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMP_EwIwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ADD_EdIdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE OR_EdIdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADC_EdIdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SBB_EdIdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AND_EdIdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SUB_EdIdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XOR_EdIdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMP_EdIdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ADD_EdIdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE OR_EdIdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADC_EdIdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SBB_EdIdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AND_EdIdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SUB_EdIdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XOR_EdIdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMP_EdIdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ADD_EwGwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE OR_EwGwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADC_EwGwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SBB_EwGwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AND_EwGwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SUB_EwGwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XOR_EwGwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMP_EwGwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ADD_EdGdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE OR_EdGdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADC_EdGdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SBB_EdGdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AND_EdGdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SUB_EdGdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XOR_EdGdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMP_EdGdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ADD_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE OR_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADC_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SBB_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AND_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SUB_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XOR_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMP_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ADD_GwEwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE OR_GwEwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADC_GwEwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SBB_GwEwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AND_GwEwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SUB_GwEwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XOR_GwEwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMP_GwEwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ADD_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE OR_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADC_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SBB_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AND_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SUB_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMP_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XOR_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ADD_GdEdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE OR_GdEdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADC_GdEdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SBB_GdEdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AND_GdEdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SUB_GdEdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMP_GdEdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XOR_GdEdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE NOT_EbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE NOT_EwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE NOT_EdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE NOT_EbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE NOT_EwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE NOT_EdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE NEG_EbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE NEG_EwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE NEG_EdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE NEG_EbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE NEG_EwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE NEG_EdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ROL_EbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ROR_EbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RCL_EbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RCR_EbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHL_EbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHR_EbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SAR_EbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ROL_EbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ROR_EbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RCL_EbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RCR_EbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHL_EbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHR_EbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SAR_EbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ROL_EwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ROR_EwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RCL_EwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RCR_EwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHL_EwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHR_EwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SAR_EwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ROL_EwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ROR_EwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RCL_EwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RCR_EwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHL_EwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHR_EwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SAR_EwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ROL_EdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ROR_EdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RCL_EdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RCR_EdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHL_EdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHR_EdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SAR_EdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ROL_EdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ROR_EdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RCL_EdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RCR_EdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHL_EdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHR_EdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SAR_EdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE TEST_EbIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE TEST_EwIwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE TEST_EdIdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE TEST_EbIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE TEST_EwIwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE TEST_EdIdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE IMUL_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE IMUL_GdEdIdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE MUL_ALEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE IMUL_ALEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE DIV_ALEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE IDIV_ALEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE MUL_EAXEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE IMUL_EAXEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE DIV_EAXEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE IDIV_EAXEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE INC_EbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE INC_EwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE INC_EdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE DEC_EbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE DEC_EwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE DEC_EdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE INC_EbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE INC_EwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE INC_EdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE DEC_EbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE DEC_EwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE DEC_EdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE CALL_EdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CALL_EwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE CALL32_Ep(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CALL16_Ep(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JMP32_Ep(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JMP16_Ep(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE JMP_EdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JMP_EwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE SLDT_Ew(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE STR_Ew(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LLDT_Ew(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LTR_Ew(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VERR_Ew(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VERW_Ew(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE SGDT_Ms(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SIDT_Ms(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LGDT_Ms(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LIDT_Ms(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SMSW_EwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SMSW_EwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LMSW_Ew(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  // LOAD methods
  BX_SMF BX_INSF_TYPE LOAD_Eb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LOAD_Ew(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LOAD_Ed(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_X86_64
  BX_SMF BX_INSF_TYPE LOAD_Eq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#endif
  BX_SMF BX_INSF_TYPE LOADU_Wdq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LOAD_Wdq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LOAD_Wss(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LOAD_Wsd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LOAD_Ww(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LOAD_Wb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_AVX
  BX_SMF BX_INSF_TYPE LOAD_Vector(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LOAD_Half_Vector(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LOAD_Quarter_Vector(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LOAD_Oct_Vector(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#endif
#if BX_SUPPORT_EVEX
  BX_SMF BX_INSF_TYPE LOAD_MASK_VectorW(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LOAD_BROADCAST_VectorD(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LOAD_BROADCAST_MASK_VectorD(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LOAD_BROADCAST_VectorQ(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LOAD_BROADCAST_MASK_VectorQ(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LOAD_BROADCAST_Half_VectorD(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LOAD_BROADCAST_MASK_Half_VectorD(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#endif

#if BX_SUPPORT_FPU == 0	// if FPU is disabled
  BX_SMF BX_INSF_TYPE FPU_ESC(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#endif

  BX_SMF BX_INSF_TYPE FWAIT(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

#if BX_SUPPORT_FPU
  // load/store
  BX_SMF BX_INSF_TYPE FLD_STi(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FLD_SINGLE_REAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FLD_DOUBLE_REAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FLD_EXTENDED_REAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FILD_WORD_INTEGER(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FILD_DWORD_INTEGER(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FILD_QWORD_INTEGER(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FBLD_PACKED_BCD(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE FST_STi(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FST_SINGLE_REAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FST_DOUBLE_REAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FSTP_EXTENDED_REAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FIST_WORD_INTEGER(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FIST_DWORD_INTEGER(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FISTP_QWORD_INTEGER(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FBSTP_PACKED_BCD(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE FISTTP16(bxInstruction_c *) BX_CPP_AttrRegparmN(1); // SSE3
  BX_SMF BX_INSF_TYPE FISTTP32(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FISTTP64(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  // control
  BX_SMF BX_INSF_TYPE FNINIT(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FNCLEX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE FRSTOR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FNSAVE(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FLDENV(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FNSTENV(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE FLDCW(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FNSTCW(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FNSTSW(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FNSTSW_AX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  // const
  BX_SMF BX_INSF_TYPE FLD1(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FLDL2T(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FLDL2E(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FLDPI(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FLDLG2(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FLDLN2(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FLDZ(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  // add
  BX_SMF BX_INSF_TYPE FADD_ST0_STj(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FADD_STi_ST0(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FADD_SINGLE_REAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FADD_DOUBLE_REAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FIADD_WORD_INTEGER(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FIADD_DWORD_INTEGER(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  // mul
  BX_SMF BX_INSF_TYPE FMUL_ST0_STj(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FMUL_STi_ST0(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FMUL_SINGLE_REAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FMUL_DOUBLE_REAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FIMUL_WORD_INTEGER (bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FIMUL_DWORD_INTEGER(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  // sub
  BX_SMF BX_INSF_TYPE FSUB_ST0_STj(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FSUBR_ST0_STj(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FSUB_STi_ST0(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FSUBR_STi_ST0(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FSUB_SINGLE_REAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FSUBR_SINGLE_REAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FSUB_DOUBLE_REAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FSUBR_DOUBLE_REAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE FISUB_WORD_INTEGER(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FISUBR_WORD_INTEGER(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FISUB_DWORD_INTEGER(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FISUBR_DWORD_INTEGER(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  // div
  BX_SMF BX_INSF_TYPE FDIV_ST0_STj(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FDIVR_ST0_STj(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FDIV_STi_ST0(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FDIVR_STi_ST0(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FDIV_SINGLE_REAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FDIVR_SINGLE_REAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FDIV_DOUBLE_REAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FDIVR_DOUBLE_REAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE FIDIV_WORD_INTEGER(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FIDIVR_WORD_INTEGER(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FIDIV_DWORD_INTEGER(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FIDIVR_DWORD_INTEGER(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  // compare
  BX_SMF BX_INSF_TYPE FCOM_STi(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FUCOM_STi(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FCOMI_ST0_STj(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FUCOMI_ST0_STj(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FCOM_SINGLE_REAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FCOM_DOUBLE_REAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FICOM_WORD_INTEGER(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FICOM_DWORD_INTEGER(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE FCOMPP(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FUCOMPP(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE FCMOVB_ST0_STj(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FCMOVE_ST0_STj(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FCMOVBE_ST0_STj(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FCMOVU_ST0_STj(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FCMOVNB_ST0_STj(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FCMOVNE_ST0_STj(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FCMOVNBE_ST0_STj(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FCMOVNU_ST0_STj(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  // misc
  BX_SMF BX_INSF_TYPE FXCH_STi(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FNOP(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FPLEGACY(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FCHS(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FABS(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FTST(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FXAM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FDECSTP(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FINCSTP(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FFREE_STi(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FFREEP_STi(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE F2XM1(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FYL2X(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FPTAN(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FPATAN(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FXTRACT(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FPREM1(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FPREM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FYL2XP1(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FSQRT(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FSINCOS(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FRNDINT(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#undef FSCALE            // <sys/param.h> is #included on Mac OS X from bochs.h
  BX_SMF BX_INSF_TYPE FSCALE(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FSIN(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FCOS(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#endif

  /* MMX */
  BX_SMF BX_INSF_TYPE PUNPCKLBW_PqQd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PUNPCKLWD_PqQd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PUNPCKLDQ_PqQd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PACKSSWB_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PCMPGTB_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PCMPGTW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PCMPGTD_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PACKUSWB_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PUNPCKHBW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PUNPCKHWD_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PUNPCKHDQ_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PACKSSDW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVD_PqEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVD_PqEdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVQ_PqQqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVQ_PqQqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PCMPEQB_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PCMPEQW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PCMPEQD_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE EMMS(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVD_EdPqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVD_EdPqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVQ_QqPqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSRLW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSRLD_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSRLQ_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMULLW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSUBUSB_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSUBUSW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PAND_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PADDUSB_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PADDUSW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PANDN_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSRAW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSRAD_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMULHW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSUBSB_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSUBSW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE POR_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PADDSB_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PADDSW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PXOR_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSLLW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSLLD_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSLLQ_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMADDWD_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSUBB_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSUBW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSUBD_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PADDB_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PADDW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PADDD_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSRLW_NqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSRAW_NqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSLLW_NqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSRLD_NqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSRAD_NqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSLLD_NqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSRLQ_NqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSLLQ_NqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  /* MMX */

#if BX_SUPPORT_3DNOW
  BX_SMF BX_INSF_TYPE PFPNACC_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PI2FW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PI2FD_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PF2IW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PF2ID_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PFNACC_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PFCMPGE_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PFMIN_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PFRCP_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PFRSQRT_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PFSUB_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PFADD_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PFCMPGT_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PFMAX_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PFRCPIT1_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PFRSQIT1_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PFSUBR_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PFACC_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PFCMPEQ_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PFMUL_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PFRCPIT2_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMULHRW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSWAPD_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#endif

  BX_SMF BX_INSF_TYPE SYSCALL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SYSRET(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  /* SSE */
  BX_SMF BX_INSF_TYPE FXSAVE(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE FXRSTOR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LDMXCSR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE STMXCSR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PREFETCH(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  /* SSE */

  /* SSE */
  BX_SMF BX_INSF_TYPE ANDPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ORPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XORPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ANDNPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVUPS_VpsWpsM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVUPS_WpsVpsM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVSS_VssWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVSS_VssWssM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVSS_WssVssM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVSD_VsdWsdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVSD_WsdVsdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVHLPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVLPS_VpsMq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVLHPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVHPS_VpsMq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVHPS_MqVps(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVAPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVAPS_VpsWpsM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVAPS_WpsVpsM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTPI2PS_VpsQqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTPI2PS_VpsQqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTSI2SS_VssEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTTPS2PI_PqWps(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTTSS2SI_GdWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTPS2PI_PqWps(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTSS2SI_GdWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE UCOMISS_VssWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE COMISS_VssWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVMSKPS_GdUps(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SQRTPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SQRTSS_VssWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RSQRTPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RSQRTSS_VssWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RCPPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RCPSS_VssWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADDPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADDSS_VssWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MULPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MULSS_VssWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SUBPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SUBSS_VssWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MINPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MINSS_VssWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE DIVPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE DIVSS_VssWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MAXPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MAXSS_VssWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSHUFW_PqQqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSHUFLW_VdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMPPS_VpsWpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMPSS_VssWssIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PINSRW_PqEwIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PEXTRW_GdNqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHUFPS_VpsWpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMOVMSKB_GdNq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMINUB_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMAXUB_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PAVGB_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PAVGW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMULHUW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMINSW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMAXSW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSADBW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MASKMOVQ_PqNq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  /* SSE */

  /* SSE2 */
  BX_SMF BX_INSF_TYPE MOVSD_VsdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTPI2PD_VpdQqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTPI2PD_VpdQqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTSI2SD_VsdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTTPD2PI_PqWpd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTTSD2SI_GdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTPD2PI_PqWpd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTSD2SI_GdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE UCOMISD_VsdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE COMISD_VsdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVMSKPD_GdUpd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SQRTPD_VpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SQRTSD_VsdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADDPD_VpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADDSD_VsdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MULPD_VpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MULSD_VsdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SUBPD_VpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SUBSD_VsdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTPS2PD_VpdWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTPD2PS_VpsWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTSD2SS_VssWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTSS2SD_VsdWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTDQ2PS_VpsWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTPS2DQ_VdqWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTTPS2DQ_VdqWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MINPD_VpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MINSD_VsdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE DIVPD_VpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE DIVSD_VsdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MAXPD_VpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MAXSD_VsdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PUNPCKLBW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PUNPCKLWD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE UNPCKLPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PACKSSWB_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PCMPGTB_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PCMPGTW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PCMPGTD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PACKUSWB_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PUNPCKHBW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PUNPCKHWD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE UNPCKHPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PACKSSDW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PUNPCKLQDQ_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PUNPCKHQDQ_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVD_VdqEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSHUFD_VdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSHUFHW_VdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PCMPEQB_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PCMPEQW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PCMPEQD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVD_EdVdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVQ_VqWqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMPPD_VpdWpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMPSD_VsdWsdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PINSRW_VdqHdqEwIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PEXTRW_GdUdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHUFPD_VpdWpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSRLW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSRLD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSRLQ_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PADDQ_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PADDQ_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMULLW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVDQ2Q_PqUdq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVQ2DQ_VdqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMOVMSKB_GdUdq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSUBUSB_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSUBUSW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMINUB_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PADDUSB_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PADDUSW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMAXUB_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PAVGB_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSRAW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSRAD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PAVGW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMULHUW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMULHW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTTPD2DQ_VqWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTPD2DQ_VqWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTDQ2PD_VpdWqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSUBSB_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSUBSW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMINSW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PADDSB_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PADDSW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMAXSW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSLLW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSLLD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSLLQ_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMULUDQ_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMULUDQ_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMADDWD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSADBW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MASKMOVDQU_VdqUdq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSUBB_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSUBW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSUBD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSUBQ_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSUBQ_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PADDB_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PADDW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PADDD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSRLW_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSRLD_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSRLQ_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSRAW_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSRAD_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSLLW_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSLLD_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSLLQ_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSRLDQ_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSLLDQ_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  /* SSE2 */

  /* SSE3 */
  BX_SMF BX_INSF_TYPE MOVDDUP_VpdWqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVSLDUP_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVSHDUP_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE HADDPD_VpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE HADDPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE HSUBPD_VpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE HSUBPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADDSUBPD_VpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADDSUBPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  /* SSE3 */

#if BX_CPU_LEVEL >= 6
  /* SSSE3 */
  BX_SMF BX_INSF_TYPE PSHUFB_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PHADDW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PHADDD_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PHADDSW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMADDUBSW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PHSUBSW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PHSUBW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PHSUBD_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSIGNB_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSIGNW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSIGND_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMULHRSW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PABSB_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PABSW_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PABSD_PqQq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PALIGNR_PqQqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE PSHUFB_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PHADDW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PHADDD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PHADDSW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMADDUBSW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PHSUBSW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PHSUBW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PHSUBD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSIGNB_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSIGNW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PSIGND_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMULHRSW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PABSB_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PABSW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PABSD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PALIGNR_VdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  /* SSSE3 */

  /* SSE4.1 */
  BX_SMF BX_INSF_TYPE PBLENDVB_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BLENDVPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BLENDVPD_VpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PTEST_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMULDQ_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PCMPEQQ_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PACKUSDW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMOVSXBW_VdqWqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMOVSXBD_VdqWdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMOVSXBQ_VdqWwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMOVSXWD_VdqWqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMOVSXWQ_VdqWdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMOVSXDQ_VdqWqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMOVZXBW_VdqWqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMOVZXBD_VdqWdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMOVZXBQ_VdqWwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMOVZXWD_VdqWqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMOVZXWQ_VdqWdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMOVZXDQ_VdqWqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMINSB_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMINSD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMINUW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMINUD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMAXSB_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMAXSD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMAXUW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMAXUD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PMULLD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PHMINPOSUW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ROUNDPS_VpsWpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ROUNDPD_VpdWpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ROUNDSS_VssWssIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ROUNDSD_VsdWsdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BLENDPS_VpsWpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BLENDPD_VpdWpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PBLENDW_VdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PEXTRB_EbdVdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PEXTRB_EbdVdqIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PEXTRW_EwdVdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PEXTRW_EwdVdqIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PEXTRD_EdVdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PEXTRD_EdVdqIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE EXTRACTPS_EdVpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE EXTRACTPS_EdVpsIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PINSRB_VdqHdqEbIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PINSRB_VdqHdqEbIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE INSERTPS_VpsHpsWssIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PINSRD_VdqHdqEdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PINSRD_VdqHdqEdIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE DPPS_VpsWpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE DPPD_VpdHpdWpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MPSADBW_VdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  /* SSE4.1 */

  /* SSE4.2 */
  BX_SMF BX_INSF_TYPE CRC32_GdEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CRC32_GdEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CRC32_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_X86_64
  BX_SMF BX_INSF_TYPE CRC32_GdEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#endif
  BX_SMF BX_INSF_TYPE PCMPGTQ_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PCMPESTRM_VdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PCMPESTRI_VdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PCMPISTRM_VdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PCMPISTRI_VdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  /* SSE4.2 */

  /* MOVBE Intel Atom(R) instruction */
  BX_SMF BX_INSF_TYPE MOVBE_GwMw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVBE_GdMd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVBE_MwGw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVBE_MdGd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_X86_64
  BX_SMF BX_INSF_TYPE MOVBE_GqMq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVBE_MqGq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#endif
  /* MOVBE Intel Atom(R) instruction */
#endif

  /* XSAVE/XRSTOR extensions */
  BX_SMF BX_INSF_TYPE XSAVE(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XSAVEC(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XRSTOR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XGETBV(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XSETBV(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  /* XSAVE/XRSTOR extensions */

#if BX_CPU_LEVEL >= 6
  /* AES instructions */
  BX_SMF BX_INSF_TYPE AESIMC_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AESENC_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AESENCLAST_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AESDEC_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AESDECLAST_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AESKEYGENASSIST_VdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PCLMULQDQ_VdqHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  /* AES instructions */

  /* SHA instructions */
  BX_SMF BX_INSF_TYPE SHA1NEXTE_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHA1MSG1_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHA1MSG2_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHA256RNDS2_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHA256MSG1_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHA256MSG2_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHA1RNDS4_VdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  /* SHA instructions */
#endif

  /* VMX instructions */
  BX_SMF BX_INSF_TYPE VMXON(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMXOFF(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMCALL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMLAUNCH(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMCLEAR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMPTRLD(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMPTRST(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMREAD_EdGd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMWRITE_GdEd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_X86_64
  BX_SMF BX_INSF_TYPE VMREAD_EqGq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMWRITE_GqEq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#endif
  BX_SMF BX_INSF_TYPE VMFUNC(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  /* VMX instructions */

  /* SVM instructions */
  BX_SMF BX_INSF_TYPE VMRUN(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMMCALL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMLOAD(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMSAVE(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SKINIT(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CLGI(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE STGI(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE INVLPGA(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  /* SVM instructions */

  /* SMX instructions */
  BX_SMF BX_INSF_TYPE GETSEC(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  /* SMX instructions */

#if BX_CPU_LEVEL >= 6
  /* VMXx2 */
  BX_SMF BX_INSF_TYPE INVEPT(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE INVVPID(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  /* VMXx2 */

  BX_SMF BX_INSF_TYPE INVPCID(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#endif

#if BX_SUPPORT_AVX
  /* AVX */
  BX_SMF BX_INSF_TYPE VZEROUPPER(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VZEROALL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VMOVSS_VssHpsWssR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVSD_VsdHpdWsdR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVAPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVAPS_VpsWpsM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVUPS_VpsWpsM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVAPS_WpsVpsM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVUPS_WpsVpsM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVLPD_VpdHpdMq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVHPD_VpdHpdMq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVLHPS_VpsHpsWps(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVHLPS_VpsHpsWps(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVSHDUP_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVSLDUP_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVDDUP_VpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VUNPCKLPS_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VUNPCKHPS_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VUNPCKLPD_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VUNPCKHPD_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVMSKPS_GdUps(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVMSKPD_GdUpd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVMSKB_GdUdq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSQRTPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSQRTPD_VpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSQRTSS_VssHpsWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSQRTSD_VsdHpdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VHADDPS_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VHADDPD_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VHSUBPS_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VHSUBPD_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VADDPS_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VADDPD_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VADDSS_VssHpsWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VADDSD_VsdHpdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMULPS_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMULPD_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMULSS_VssHpsWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMULSD_VsdHpdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSUBPS_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSUBPD_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSUBSS_VssHpsWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSUBSD_VsdHpdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTSS2SD_VsdWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTSD2SS_VssWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTDQ2PS_VpsWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTPS2DQ_VdqWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTTPS2DQ_VdqWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTPS2PD_VpdWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTPD2PS_VpsWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTPD2DQ_VdqWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTDQ2PD_VpdWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTTPD2DQ_VdqWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTSI2SD_VsdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTSI2SS_VssEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTSI2SD_VsdEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTSI2SS_VssEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMINPS_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMINPD_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMINSS_VssHpsWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMINSD_VsdHpdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VDIVPS_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VDIVPD_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VDIVSS_VssHpsWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VDIVSD_VsdHpdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMAXPS_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMAXPD_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMAXSS_VssHpsWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMAXSD_VsdHpdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCMPPS_VpsHpsWpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCMPSS_VssHpsWssIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCMPPD_VpdHpdWpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCMPSD_VsdHpdWsdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VADDSUBPD_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VADDSUBPS_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VROUNDPS_VpsWpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VROUNDPD_VpdWpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VROUNDSS_VssHpsWssIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VROUNDSD_VsdHpdWsdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VDPPS_VpsHpsWpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VRSQRTPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VRSQRTSS_VssHpsWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VRCPPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VRCPSS_VssHpsWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSHUFPS_VpsHpsWpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSHUFPD_VpdHpdWpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VBLENDPS_VpsHpsWpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VBLENDPD_VpdHpdWpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPBLENDVB_VdqHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPTEST_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VTESTPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VTESTPD_VpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VANDPS_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VANDNPS_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VORPS_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VXORPS_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VBROADCASTF128_VdqMdq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VBLENDVPS_VpsHpsWpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VBLENDVPD_VpdHpdWpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VINSERTF128_VdqHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VEXTRACTF128_WdqVdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VEXTRACTF128_WdqVdqIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPERMILPS_VpsWpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPERMILPS_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPERMILPD_VpdWpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPERMILPD_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPERM2F128_VdqHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMASKMOVPS_VpsHpsMps(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMASKMOVPD_VpdHpdMpd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMASKMOVPS_MpsHpsVps(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMASKMOVPD_MpdHpdVpd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VCVTPH2PS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTPS2PH_WpsVpsIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  /* AVX */

  /* AVX2 */
  BX_SMF BX_INSF_TYPE VPCMPEQB_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCMPEQW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCMPEQD_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCMPEQQ_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCMPGTB_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCMPGTW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCMPGTD_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCMPGTQ_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMINSB_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMINSW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMINSD_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMINSQ_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMINUB_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMINUW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMINUD_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMINUQ_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMAXSB_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMAXSW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMAXSD_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMAXSQ_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMAXUB_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMAXUW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMAXUD_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMAXUQ_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSIGNB_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSIGNW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSIGND_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPADDB_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPADDW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPADDD_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPADDQ_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSUBB_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSUBW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSUBD_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSUBQ_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPABSB_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPABSW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPABSD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPABSQ_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSUBSB_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSUBSW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSUBUSB_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSUBUSW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPADDSB_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPADDSW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPADDUSB_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPADDUSW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPAVGB_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPAVGW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPHADDW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPHADDD_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPHADDSW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPHSUBW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPHSUBD_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPHSUBSW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSHUFHW_VdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSHUFLW_VdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPACKUSWB_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPACKSSWB_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPACKUSDW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPACKSSDW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPUNPCKLBW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPUNPCKHBW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPUNPCKLWD_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPUNPCKHWD_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMULLQ_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMULLD_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMULLW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMULHW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMULHUW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMULDQ_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMULUDQ_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMULHRSW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMADDUBSW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMADDWD_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMPSADBW_VdqHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPBLENDW_VdqHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSADBW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSHUFB_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRLW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRLD_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRLQ_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSLLW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSLLD_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSLLQ_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRAW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRAD_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRAQ_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRLW_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRLD_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRLQ_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSLLW_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSLLD_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSLLQ_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRAW_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRAD_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRAQ_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPROLD_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPROLQ_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPRORD_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPRORQ_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRLDQ_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSLLDQ_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPALIGNR_VdqHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPMOVSXBW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVSXBD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVSXBQ_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVSXWD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVSXWQ_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVSXDQ_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPMOVZXBW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVZXBD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVZXBQ_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVZXWD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVZXWQ_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVZXDQ_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPERMD_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPERMQ_VdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPSRAVW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRAVD_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRAVQ_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSLLVW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSLLVD_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSLLVQ_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRLVW_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRLVD_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRLVQ_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPROLVD_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPROLVQ_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPRORVD_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPRORVQ_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPBROADCASTB_VdqWbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPBROADCASTW_VdqWwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPBROADCASTD_VdqWdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPBROADCASTQ_VdqWqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VGATHERDPS_VpsHps(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VGATHERQPS_VpsHps(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VGATHERDPD_VpdHpd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VGATHERQPD_VpdHpd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  /* AVX2 */

  /* AVX2 FMA */
  BX_SMF BX_INSF_TYPE VFMADDPD_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFMADDPS_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFMADDSD_VpdHsdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFMADDSS_VpsHssWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFMADDSUBPD_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFMADDSUBPS_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFMSUBADDPD_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFMSUBADDPS_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFMSUBPD_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFMSUBPS_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFMSUBSD_VpdHsdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFMSUBSS_VpsHssWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFNMADDPD_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFNMADDPS_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFNMADDSD_VpdHsdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFNMADDSS_VpsHssWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFNMSUBPD_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFNMSUBPS_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFNMSUBSD_VpdHsdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFNMSUBSS_VpsHssWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  /* AVX2 FMA */

  /* BMI */
  BX_SMF BX_INSF_TYPE ANDN_GdBdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MULX_GdBdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BLSI_BdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BLSMSK_BdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BLSR_BdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RORX_GdEdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHLX_GdEdBdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHRX_GdEdBdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SARX_GdEdBdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BEXTR_GdEdBdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BZHI_GdBdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PEXT_GdBdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PDEP_GdBdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ANDN_GqBqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MULX_GqBqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BLSI_BqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BLSMSK_BqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BLSR_BqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RORX_GqEqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHLX_GqEqBqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHRX_GqEqBqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SARX_GqEqBqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BEXTR_GqEqBqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BZHI_GqBqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PEXT_GqBqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PDEP_GqBqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  /* BMI */

  /* FMA4 specific handlers (AMD) */
  BX_SMF BX_INSF_TYPE VFMADDSS_VssHssWssVIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFMADDSD_VsdHsdWsdVIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFMSUBSS_VssHssWssVIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFMSUBSD_VsdHsdWsdVIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFNMADDSS_VssHssWssVIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFNMADDSD_VsdHsdWsdVIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFNMSUBSS_VssHssWssVIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFNMSUBSD_VsdHsdWsdVIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  /* FMA4 specific handlers (AMD) */

  /* XOP (AMD) */
  BX_SMF BX_INSF_TYPE VPCMOV_VdqHdqWdqVIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPPERM_VdqHdqWdqVIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSHAB_VdqWdqHdq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSHAW_VdqWdqHdq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSHAD_VdqWdqHdq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSHAQ_VdqWdqHdq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPROTB_VdqWdqHdq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPROTW_VdqWdqHdq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPROTD_VdqWdqHdq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPROTQ_VdqWdqHdq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSHLB_VdqWdqHdq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSHLW_VdqWdqHdq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSHLD_VdqWdqHdq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSHLQ_VdqWdqHdq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMACSSWW_VdqHdqWdqVIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMACSSWD_VdqHdqWdqVIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMACSSDQL_VdqHdqWdqVIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMACSSDD_VdqHdqWdqVIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMACSSDQH_VdqHdqWdqVIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMACSWW_VdqHdqWdqVIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMACSWD_VdqHdqWdqVIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMACSDQL_VdqHdqWdqVIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMACSDD_VdqHdqWdqVIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMACSDQH_VdqHdqWdqVIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMADCSSWD_VdqHdqWdqVIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMADCSWD_VdqHdqWdqVIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPROTB_VdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPROTW_VdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPROTD_VdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPROTQ_VdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCOMB_VdqHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCOMW_VdqHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCOMD_VdqHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCOMQ_VdqHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCOMUB_VdqHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCOMUW_VdqHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCOMUD_VdqHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCOMUQ_VdqHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFRCZPS_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFRCZPD_VpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFRCZSS_VssWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFRCZSD_VsdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPHADDBW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPHADDBD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPHADDBQ_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPHADDWD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPHADDWQ_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPHADDDQ_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPHADDUBW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPHADDUBD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPHADDUBQ_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPHADDUWD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPHADDUWQ_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPHADDUDQ_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPHSUBBW_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPHSUBWD_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPHSUBDQ_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPERMIL2PS_VdqHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPERMIL2PD_VdqHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  /* XOP (AMD) */

  /* TBM (AMD) */
  BX_SMF BX_INSF_TYPE BEXTR_GdEdIdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BLCFILL_BdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BLCI_BdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BLCIC_BdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BLCMSK_BdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BLCS_BdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BLSFILL_BdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BLSIC_BdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE T1MSKC_BdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE TZMSK_BdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE BEXTR_GqEqIdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BLCFILL_BqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BLCI_BqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BLCIC_BqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BLCMSK_BqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BLCS_BqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BLSFILL_BqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BLSIC_BqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE T1MSKC_BqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE TZMSK_BqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  /* TBM (AMD) */
#endif

#if BX_SUPPORT_AVX
  // AVX512 OPMASK instructions (VEX encoded)
  BX_SMF BX_INSF_TYPE KADDB_KGbKHbKEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KANDB_KGbKHbKEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KANDNB_KGbKHbKEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KMOVB_KGbKEbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KMOVB_KGbKEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KMOVB_KEbKGbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KMOVB_KGbEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KMOVB_GdKEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KNOTB_KGbKEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KORB_KGbKHbKEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KORTESTB_KGbKEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KSHIFTLB_KGbKEbIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KSHIFTRB_KGbKEbIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KXNORB_KGbKHbKEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KXORB_KGbKHbKEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KTESTB_KGbKEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE KADDW_KGwKHwKEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KANDW_KGwKHwKEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KANDNW_KGwKHwKEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KMOVW_KGwKEwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KMOVW_KGwKEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KMOVW_KEwKGwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KMOVW_KGwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KMOVW_GdKEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KUNPCKBW_KGwKHbKEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KNOTW_KGwKEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KORW_KGwKHwKEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KORTESTW_KGwKEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KSHIFTLW_KGwKEwIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KSHIFTRW_KGwKEwIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KXNORW_KGwKHwKEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KXORW_KGwKHwKEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KTESTW_KGwKEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE KADDD_KGdKHdKEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KANDD_KGdKHdKEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KANDND_KGdKHdKEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KMOVD_KGdKEdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KMOVD_KGdKEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KMOVD_KEdKGdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KMOVD_KGdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KMOVD_GdKEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KUNPCKWD_KGdKHwKEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KNOTD_KGdKEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KORD_KGdKHdKEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KORTESTD_KGdKEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KSHIFTLD_KGdKEdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KSHIFTRD_KGdKEdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KXNORD_KGdKHdKEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KXORD_KGdKHdKEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KTESTD_KGdKEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE KADDQ_KGqKHqKEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KANDQ_KGqKHqKEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KANDNQ_KGqKHqKEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KMOVQ_KGqKEqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KMOVQ_KGqKEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KMOVQ_KEqKGqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KMOVQ_KGqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KMOVQ_GqKEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KUNPCKDQ_KGqKHdKEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KNOTQ_KGqKEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KORQ_KGqKHqKEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KORTESTQ_KGqKEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KSHIFTLQ_KGqKEqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KSHIFTRQ_KGqKEqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KXNORQ_KGqKHqKEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KXORQ_KGqKHqKEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE KTESTQ_KGqKEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  // AVX512 OPMASK instructions (VEX encoded)
#endif

#if BX_SUPPORT_EVEX
  BX_SMF BX_INSF_TYPE VADDPS_MASK_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VADDPD_MASK_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VADDSS_MASK_VssHpsWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VADDSD_MASK_VsdHpdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSUBPS_MASK_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSUBPD_MASK_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSUBSS_MASK_VssHpsWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSUBSD_MASK_VsdHpdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMULPS_MASK_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMULPD_MASK_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMULSS_MASK_VssHpsWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMULSD_MASK_VsdHpdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VDIVPS_MASK_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VDIVPD_MASK_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VDIVSS_MASK_VssHpsWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VDIVSD_MASK_VsdHpdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMINPS_MASK_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMINPD_MASK_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMINSS_MASK_VssHpsWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMINSD_MASK_VsdHpdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMAXPS_MASK_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMAXPD_MASK_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMAXSS_MASK_VssHpsWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMAXSD_MASK_VsdHpdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSQRTPS_MASK_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSQRTPD_MASK_VpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSQRTSS_MASK_VssHpsWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSQRTSD_MASK_VsdHpdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VFPCLASSPS_MASK_KGwWpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFPCLASSPD_MASK_KGbWpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFPCLASSSS_MASK_KGbWssIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFPCLASSSD_MASK_KGbWsdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VGETEXPPS_MASK_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VGETEXPPD_MASK_VpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VGETEXPSS_MASK_VssHpsWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VGETEXPSD_MASK_VsdHpdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VGETMANTPS_MASK_VpsWpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VGETMANTPD_MASK_VpdWpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VGETMANTSS_MASK_VssHpsWssIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VGETMANTSD_MASK_VsdHpdWsdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VRNDSCALEPS_MASK_VpsWpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VRNDSCALEPD_MASK_VpdWpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VRNDSCALESS_MASK_VssHpsWssIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VRNDSCALESD_MASK_VsdHpdWsdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VREDUCEPS_MASK_VpsWpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VREDUCEPD_MASK_VpdWpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VREDUCESS_MASK_VssHpsWssIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VREDUCESD_MASK_VsdHpdWsdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VSCALEFPS_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSCALEFPD_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSCALEFSS_VssHpsWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSCALEFSD_VsdHpdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VSCALEFPS_MASK_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSCALEFPD_MASK_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSCALEFSS_MASK_VssHpsWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSCALEFSD_MASK_VsdHpdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VRANGEPS_MASK_VpsHpsWpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VRANGEPD_MASK_VpdHpdWpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VRANGESS_MASK_VssHpsWssIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VRANGESD_MASK_VsdHpdWsdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VRCP14PS_MASK_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VRCP14PD_MASK_VpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VRCP14SS_MASK_VssHpsWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VRCP14SD_MASK_VsdHpdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VRSQRT14PS_MASK_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VRSQRT14PD_MASK_VpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VRSQRT14SS_MASK_VssHpsWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VRSQRT14SD_MASK_VsdHpdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VCVTSS2USI_GdWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTSS2USI_GqWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTSD2USI_GdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTSD2USI_GqWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VCVTTSS2USI_GdWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTTSS2USI_GqWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTTSD2USI_GdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTTSD2USI_GqWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VCVTUSI2SD_VsdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTUSI2SS_VssEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTUSI2SD_VsdEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTUSI2SS_VssEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VCVTTPS2UDQ_VdqWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTTPS2UDQ_MASK_VdqWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTTPD2UDQ_VdqWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTTPD2UDQ_MASK_VdqWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VCVTPS2UDQ_VdqWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTPS2UDQ_MASK_VdqWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTPD2UDQ_VdqWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTPD2UDQ_MASK_VdqWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VCVTUDQ2PS_VpsWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTUDQ2PS_MASK_VpsWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTUDQ2PD_VpdWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTUDQ2PD_MASK_VpdWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VCVTQQ2PS_VpsWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTQQ2PS_MASK_VpsWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTUQQ2PS_VpsWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTUQQ2PS_MASK_VpsWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VCVTQQ2PD_VpdWdqR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTQQ2PD_MASK_VpdWdqR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTUQQ2PD_VpdWdqR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTUQQ2PD_MASK_VpdWdqR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VCVTPS2QQ_VdqWpsR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTPS2QQ_MASK_VdqWpsR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTTPS2QQ_VdqWpsR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTTPS2QQ_MASK_VdqWpsR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTPS2UQQ_VdqWpsR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTPS2UQQ_MASK_VdqWpsR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTTPS2UQQ_VdqWpsR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTTPS2UQQ_MASK_VdqWpsR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VCVTPD2QQ_VdqWpdR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTPD2QQ_MASK_VdqWpdR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTTPD2QQ_VdqWpdR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTTPD2QQ_MASK_VdqWpdR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTPD2UQQ_VdqWpdR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTPD2UQQ_MASK_VdqWpdR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTTPD2UQQ_VdqWpdR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTTPD2UQQ_MASK_VdqWpdR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VCVTPD2PS_MASK_VpsWpdR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTPS2PD_MASK_VpdWpsR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTSS2SD_MASK_VsdWssR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTSD2SS_MASK_VssWsdR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VCVTPS2DQ_MASK_VdqWpsR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTTPS2DQ_MASK_VdqWpsR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTDQ2PS_MASK_VpsWdqR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VCVTPD2DQ_MASK_VdqWpdR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTTPD2DQ_MASK_VdqWpdR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTDQ2PD_MASK_VpdWdqR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VCVTPH2PS_MASK_VpsWpsR(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTPS2PH_MASK_WpsVpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCVTPS2PH_MASK_WpsVpsIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPABSB_MASK_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPABSW_MASK_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPABSD_MASK_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPABSQ_MASK_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPADDD_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSUBD_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPANDD_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPANDND_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPORD_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPXORD_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMAXSD_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMAXUD_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMINSD_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMINUD_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMULLD_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VUNPCKLPS_MASK_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VUNPCKHPS_MASK_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRAVD_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRLVD_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSLLVD_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPROLVD_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPRORVD_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRLD_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRAD_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSLLD_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMADDWD_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPADDQ_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSUBQ_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPANDQ_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPANDNQ_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPORQ_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPXORQ_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMAXSQ_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMAXUQ_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMINSQ_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMINUQ_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMULLQ_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VUNPCKLPD_MASK_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VUNPCKHPD_MASK_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMULDQ_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMULUDQ_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRAVQ_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRLVQ_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSLLVQ_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPROLVQ_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPRORVQ_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRLQ_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRAQ_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSLLQ_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPROLD_MASK_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPROLQ_MASK_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPRORD_MASK_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPRORQ_MASK_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRLW_MASK_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRLD_MASK_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRLQ_MASK_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRAW_MASK_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRAD_MASK_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRAQ_MASK_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSLLW_MASK_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSLLD_MASK_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSLLQ_MASK_UdqIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPSUBB_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSUBSB_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSUBUSB_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSUBW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSUBSW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSUBUSW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPADDB_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPADDSB_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPADDUSB_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPADDW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPADDSW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPADDUSW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPMINSB_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMINUB_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMAXUB_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMAXSB_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMINSW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMINUW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMAXSW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMAXUW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPSRLW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRAW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSLLW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPSRAVW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSRLVW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSLLVW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPAVGB_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPAVGW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMADDUBSW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMULLW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMULHW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMULHUW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMULHRSW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPACKSSWB_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPACKUSWB_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPACKSSDW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPACKUSDW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPUNPCKLBW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPUNPCKHBW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPUNPCKLWD_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPUNPCKHWD_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VMOVAPS_MASK_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVAPS_MASK_VpsWpsM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVAPS_MASK_WpsVpsM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVAPD_MASK_VpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVAPD_MASK_VpdWpdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVAPD_MASK_WpdVpdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VMOVUPS_MASK_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVUPS_MASK_VpsWpsM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVUPS_MASK_WpsVpsM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVUPD_MASK_VpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVUPD_MASK_VpdWpdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVUPD_MASK_WpdVpdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VMOVDQU8_MASK_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVDQU8_MASK_VdqWdqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVDQU8_MASK_WdqVdqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VMOVDQU16_MASK_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVDQU16_MASK_VdqWdqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVDQU16_MASK_WdqVdqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VMOVSD_MASK_VsdWsdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVSS_MASK_VssWssM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVSD_MASK_WsdVsdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVSS_MASK_WssVssM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVSD_MASK_VsdHpdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVSS_MASK_VssHpsWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VMOVSHDUP_MASK_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVSLDUP_MASK_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VMOVDDUP_MASK_VpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VFMADDPD_MASK_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFMADDPS_MASK_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFMADDSD_MASK_VpdHsdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFMADDSS_MASK_VpsHssWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFMADDSUBPD_MASK_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFMADDSUBPS_MASK_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFMSUBADDPD_MASK_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFMSUBADDPS_MASK_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFMSUBPD_MASK_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFMSUBPS_MASK_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFMSUBSD_MASK_VpdHsdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFMSUBSS_MASK_VpsHssWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFNMADDPD_MASK_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFNMADDPS_MASK_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFNMADDSD_MASK_VpdHsdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFNMADDSS_MASK_VpsHssWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFNMSUBPD_MASK_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFNMSUBPS_MASK_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFNMSUBSD_MASK_VpdHsdWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFNMSUBSS_MASK_VpsHssWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VFIXUPIMMSS_MASK_VssHssWssIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFIXUPIMMSD_MASK_VsdHsdWsdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFIXUPIMMPS_VpsHpsWpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFIXUPIMMPD_VpdHpdWpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFIXUPIMMPS_MASK_VpsHpsWpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VFIXUPIMMPD_MASK_VpdHpdWpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VBLENDMPS_MASK_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VBLENDMPD_MASK_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPBLENDMB_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPBLENDMW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPCMPB_MASK_KGqHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCMPUB_MASK_KGqHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCMPW_MASK_KGdHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCMPUW_MASK_KGdHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCMPD_MASK_KGwHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCMPUD_MASK_KGwHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCMPQ_MASK_KGbHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCMPUQ_MASK_KGbHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPCMPEQB_MASK_KGqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCMPGTB_MASK_KGqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCMPEQW_MASK_KGdHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCMPGTW_MASK_KGdHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCMPEQD_MASK_KGwHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCMPGTD_MASK_KGwHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCMPEQQ_MASK_KGbHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCMPGTQ_MASK_KGbHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPTESTMB_MASK_KGqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPTESTNMB_MASK_KGqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPTESTMW_MASK_KGdHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPTESTNMW_MASK_KGdHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPTESTMD_MASK_KGwHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPTESTNMD_MASK_KGwHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPTESTMQ_MASK_KGbHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPTESTNMQ_MASK_KGbHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VCMPPS_MASK_KGwHpsWpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCMPPD_MASK_KGbHpdWpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCMPSS_MASK_KGbHssWssIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCMPSD_MASK_KGbHsdWsdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPSHUFB_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPERMQ_MASK_VdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSHUFPS_MASK_VpsHpsWpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSHUFPD_MASK_VpdHpdWpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSHUFLW_MASK_VdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPSHUFHW_MASK_VdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPERMILPS_MASK_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPERMILPD_MASK_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPERMILPS_MASK_VpsWpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPERMILPD_MASK_VpdWpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VSHUFF32x4_MASK_VpsHpsWpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSHUFF64x2_MASK_VpdHpdWpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VALIGND_MASK_VdqHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VALIGNQ_MASK_VdqHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPALIGNR_MASK_VdqHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VDBPSADBW_MASK_VdqHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPERMI2B_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPERMI2W_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPERMT2B_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPERMT2W_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPERMI2PS_MASK_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPERMI2PD_MASK_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPERMT2PS_MASK_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPERMT2PD_MASK_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPERMB_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPERMW_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPERMPS_MASK_VpsHpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPERMPD_MASK_VpdHpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VINSERTF32x4_MASK_VpsHpsWpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VINSERTF64x2_MASK_VpdHpdWpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VINSERTF64x4_VpdHpdWpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VINSERTF64x4_MASK_VpdHpdWpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VINSERTF32x8_MASK_VpsHpsWpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VEXTRACTF32x4_MASK_WpsVpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VEXTRACTF32x4_MASK_WpsVpsIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VEXTRACTF64x4_WpdVpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VEXTRACTF64x4_WpdVpdIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VEXTRACTF64x4_MASK_WpdVpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VEXTRACTF64x4_MASK_WpdVpdIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VEXTRACTF32x8_MASK_WpsVpsIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VEXTRACTF32x8_MASK_WpsVpsIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VEXTRACTF64x2_MASK_WpdVpdIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VEXTRACTF64x2_MASK_WpdVpdIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPBROADCASTB_MASK_VdqWbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPBROADCASTW_MASK_VdqWwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPBROADCASTD_MASK_VdqWdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPBROADCASTQ_MASK_VdqWqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPBROADCASTB_VdqEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPBROADCASTW_VdqEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPBROADCASTD_VdqEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPBROADCASTQ_VdqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPBROADCASTB_MASK_VdqEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPBROADCASTW_MASK_VdqEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPBROADCASTD_MASK_VdqEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPBROADCASTQ_MASK_VdqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VBROADCASTF32x2_MASK_VpsWqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VBROADCASTF64x2_MASK_VpdMpd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VBROADCASTF32x4_MASK_VpsMps(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VBROADCASTF64x4_VpdMpd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VBROADCASTF32x8_MASK_VpsMps(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VBROADCASTF64x4_MASK_VpdMpd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPTERNLOGD_VdqHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPTERNLOGQ_VdqHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPTERNLOGD_MASK_VdqHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPTERNLOGQ_MASK_VdqHdqWdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VGATHERDPS_MASK_VpsVSib(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VGATHERQPS_MASK_VpsVSib(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VGATHERDPD_MASK_VpdVSib(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VGATHERQPD_MASK_VpdVSib(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VSCATTERDPS_MASK_VSibVps(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSCATTERQPS_MASK_VSibVps(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSCATTERDPD_MASK_VSibVpd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VSCATTERQPD_MASK_VSibVpd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VCOMPRESSPS_MASK_WpsVps(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VCOMPRESSPD_MASK_WpdVpd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VEXPANDPS_MASK_VpsWpsR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VEXPANDPD_MASK_VpdWpdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPMOVQB_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVDB_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVWB_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVDW_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVQW_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVQD_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPMOVQB_MASK_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVDB_MASK_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVWB_MASK_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVDW_MASK_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVQW_MASK_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVQD_MASK_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPMOVQB_MASK_WdqVdqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVDB_MASK_WdqVdqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVWB_MASK_WdqVdqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVDW_MASK_WdqVdqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVQW_MASK_WdqVdqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVQD_MASK_WdqVdqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPMOVUSQB_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVUSDB_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVUSWB_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVUSDW_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVUSQW_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVUSQD_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPMOVUSQB_MASK_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVUSDB_MASK_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVUSWB_MASK_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVUSDW_MASK_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVUSQW_MASK_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVUSQD_MASK_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPMOVUSQB_MASK_WdqVdqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVUSDB_MASK_WdqVdqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVUSWB_MASK_WdqVdqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVUSDW_MASK_WdqVdqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVUSQW_MASK_WdqVdqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVUSQD_MASK_WdqVdqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPMOVSQB_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVSDB_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVSWB_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVSDW_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVSQW_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVSQD_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPMOVSQB_MASK_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVSDB_MASK_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVSWB_MASK_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVSDW_MASK_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVSQW_MASK_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVSQD_MASK_WdqVdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPMOVSQB_MASK_WdqVdqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVSDB_MASK_WdqVdqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVSWB_MASK_WdqVdqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVSDW_MASK_WdqVdqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVSQW_MASK_WdqVdqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVSQD_MASK_WdqVdqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPMOVSXBW_MASK_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVSXBD_MASK_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVSXBQ_MASK_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVSXWD_MASK_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVSXWQ_MASK_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVSXDQ_MASK_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPMOVZXBW_MASK_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVZXBD_MASK_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVZXBQ_MASK_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVZXWD_MASK_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVZXWQ_MASK_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVZXDQ_MASK_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPCONFLICTD_MASK_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPCONFLICTQ_MASK_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPLZCNTD_MASK_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPLZCNTQ_MASK_VdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPBROADCASTMB2Q_VdqKEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPBROADCASTMW2D_VdqKEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPMOVM2B_VdqKEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVM2W_VdqKEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVM2D_VdqKEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVM2Q_VdqKEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPMOVB2M_KGqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVW2M_KGdWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVD2M_KGwWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMOVQ2M_KGbWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPMADD52LUQ_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMADD52LUQ_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMADD52HUQ_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMADD52HUQ_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE VPMULTISHIFTQB_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE VPMULTISHIFTQB_MASK_VdqHdqWdqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#endif

  BX_SMF BX_INSF_TYPE LZCNT_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LZCNT_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_X86_64
  BX_SMF BX_INSF_TYPE LZCNT_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#endif

  /* BMI - TZCNT */
  BX_SMF BX_INSF_TYPE TZCNT_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE TZCNT_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_X86_64
  BX_SMF BX_INSF_TYPE TZCNT_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#endif
  /* BMI - TZCNT */

  /* SSE4A */
  BX_SMF BX_INSF_TYPE EXTRQ_UdqIbIb(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE EXTRQ_VdqUq(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE INSERTQ_VdqUqIbIb(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE INSERTQ_VdqUdq(bxInstruction_c *i) BX_CPP_AttrRegparmN(1);
  /* SSE4A */

  BX_SMF BX_INSF_TYPE CMPXCHG8B(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RETnear32_Iw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RETnear32(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RETnear16_Iw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RETnear16(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RETfar32_Iw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RETfar16_Iw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE XADD_EbGbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XADD_EwGwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XADD_EdGdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE XADD_EbGbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XADD_EwGwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XADD_EdGdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE CMOVO_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVNO_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVB_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVNB_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVZ_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVNZ_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVBE_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVNBE_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVS_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVNS_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVP_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVNP_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVL_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVNL_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVLE_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVNLE_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE CMOVO_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVNO_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVB_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVNB_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVZ_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVNZ_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVBE_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVNBE_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVS_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVNS_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVP_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVNP_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVL_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVNL_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVLE_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVNLE_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE CWDE(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CDQ(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE CMPXCHG_EbGbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMPXCHG_EwGwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMPXCHG_EdGdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE CMPXCHG_EbGbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMPXCHG_EwGwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMPXCHG_EdGdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE MUL_AXEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE IMUL_AXEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE DIV_AXEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE IDIV_AXEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE IMUL_GwEwIwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE IMUL_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE NOP(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PAUSE(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_EbIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_EwIwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_EdIdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE PUSH_EwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PUSH_EwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PUSH_EdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PUSH_EdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE POP_EwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE POP_EwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE POP_EdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE POP_EdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE POPCNT_GwEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE POPCNT_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_X86_64
  BX_SMF BX_INSF_TYPE POPCNT_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#endif

  BX_SMF BX_INSF_TYPE ADCX_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADOX_GdEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_X86_64
  BX_SMF BX_INSF_TYPE ADCX_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADOX_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#endif

  // SMAP
  BX_SMF BX_INSF_TYPE CLAC(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE STAC(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  // SMAP

  // RDRAND/RDSEED
  BX_SMF BX_INSF_TYPE RDRAND_Ew(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RDRAND_Ed(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_X86_64
  BX_SMF BX_INSF_TYPE RDRAND_Eq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#endif

  BX_SMF BX_INSF_TYPE RDSEED_Ew(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RDSEED_Ed(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_X86_64
  BX_SMF BX_INSF_TYPE RDSEED_Eq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#endif

#if BX_SUPPORT_X86_64
  // 64 bit extensions
  BX_SMF BX_INSF_TYPE ADD_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE OR_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADC_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SBB_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AND_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SUB_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XOR_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMP_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ADD_GqEqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE OR_GqEqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADC_GqEqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SBB_GqEqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AND_GqEqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SUB_GqEqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XOR_GqEqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMP_GqEqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ADD_EqGqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE OR_EqGqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADC_EqGqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SBB_EqGqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AND_EqGqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SUB_EqGqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XOR_EqGqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMP_EqGqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ADD_EqIdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE OR_EqIdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADC_EqIdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SBB_EqIdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AND_EqIdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SUB_EqIdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XOR_EqIdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMP_EqIdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ADD_EqIdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE OR_EqIdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ADC_EqIdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SBB_EqIdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE AND_EqIdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SUB_EqIdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XOR_EqIdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMP_EqIdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE TEST_EqGqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE TEST_EqGqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE TEST_RAXId(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE XCHG_EqGqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XCHG_EqGqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE LEA_GqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE MOV_RAXOq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_OqRAX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_EAXOq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_OqEAX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_AXOq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_OqAX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_ALOq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_OqAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE MOV_EqGqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_GqEqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_EqIdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_EqIdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE MOV64S_EqGqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV64S_GqEqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  // repeatable instructions
  BX_SMF BX_INSF_TYPE REP_MOVSQ_YqXq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE REP_CMPSQ_XqYq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE REP_STOSQ_YqRAX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE REP_LODSQ_RAXXq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE REP_SCASQ_RAXYq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  // qualified by address size
  BX_SMF void CMPSB64_XbYb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void CMPSW64_XwYw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void CMPSD64_XdYd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void SCASB64_ALYb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void SCASW64_AXYw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void SCASD64_EAXYd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void LODSB64_ALXb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void LODSW64_AXXw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void LODSD64_EAXXd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void STOSB64_YbAL(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void STOSW64_YwAX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void STOSD64_YdEAX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void MOVSB64_YbXb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void MOVSW64_YwXw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void MOVSD64_YdXd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF void CMPSQ32_XqYq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void CMPSQ64_XqYq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void SCASQ32_RAXYq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void SCASQ64_RAXYq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void LODSQ32_RAXXq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void LODSQ64_RAXXq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void STOSQ32_YqRAX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void STOSQ64_YqRAX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void MOVSQ32_YqXq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void MOVSQ64_YqXq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF void INSB64_YbDX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void INSW64_YwDX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void INSD64_YdDX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF void OUTSB64_DXXb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void OUTSW64_DXXw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF void OUTSD64_DXXd(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE CALL_Jq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JMP_Jq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE JO_Jq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JNO_Jq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JB_Jq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JNB_Jq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JZ_Jq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JNZ_Jq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JBE_Jq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JNBE_Jq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JS_Jq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JNS_Jq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JP_Jq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JNP_Jq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JL_Jq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JNL_Jq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JLE_Jq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JNLE_Jq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ENTER64_IwIb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LEAVE64(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE IRET64(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE MOV_CR0Rq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_CR2Rq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_CR3Rq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_CR4Rq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_RqCR0(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_RqCR2(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_RqCR3(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_RqCR4(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_DqRq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV_RqDq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE SHLD_EqGqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHLD_EqGqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHRD_EqGqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHRD_EqGqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE MOV64_GdEdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOV64_EdGdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE MOVZX_GqEbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVZX_GqEwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVSX_GqEbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVSX_GqEwM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVSX_GqEdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE MOVZX_GqEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVZX_GqEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVSX_GqEbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVSX_GqEwR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVSX_GqEdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE BSF_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BSR_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE BT_EqGqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTS_EqGqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTR_EqGqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTC_EqGqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE BT_EqGqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTS_EqGqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTR_EqGqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTC_EqGqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE BT_EqIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTS_EqIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTR_EqIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTC_EqIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE BT_EqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTS_EqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTR_EqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BTC_EqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE BSWAP_RRX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ROL_EqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ROR_EqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RCL_EqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RCR_EqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHL_EqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHR_EqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SAR_EqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE ROL_EqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE ROR_EqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RCL_EqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RCR_EqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHL_EqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SHR_EqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SAR_EqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE NOT_EqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE NEG_EqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE NOT_EqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE NEG_EqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE TEST_EqIdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE TEST_EqIdM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE MUL_RAXEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE IMUL_RAXEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE DIV_RAXEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE IDIV_RAXEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE IMUL_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE IMUL_GqEqIdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE INC_EqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE DEC_EqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE INC_EqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE DEC_EqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CALL_EqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CALL64_Ep(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JMP_EqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JMP64_Ep(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PUSHF_Fq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE POPF_Fq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE CMPXCHG_EqGqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMPXCHG_EqGqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE CDQE(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CQO(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE XADD_EqGqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE XADD_EqGqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE RETnear64_Iw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RETnear64(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RETfar64_Iw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE CMOVO_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVNO_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVB_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVNB_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVZ_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVNZ_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVBE_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVNBE_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVS_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVNS_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVP_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVNP_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVL_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVNL_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVLE_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CMOVNLE_GqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE MOV_RRXIq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PUSH_EqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PUSH_EqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE POP_EqM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE POP_EqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE PUSH64_Id(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PUSH64_Sw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE POP64_Sw(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE LSS_GqMp(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LFS_GqMp(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LGS_GqMp(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE SGDT64_Ms(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SIDT64_Ms(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LGDT64_Ms(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LIDT64_Ms(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE CMPXCHG16B(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE SWAPGS(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RDFSBASE_Ed(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RDGSBASE_Ed(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RDFSBASE_Eq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RDGSBASE_Eq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE WRFSBASE_Ed(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE WRGSBASE_Ed(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE WRFSBASE_Eq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE WRGSBASE_Eq(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE LOOPNE64_Jb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LOOPE64_Jb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE LOOP64_Jb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE JRCXZ_Jb(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE MOVQ_EqPqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVQ_EqVqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVQ_PqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MOVQ_VdqEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE CVTSI2SS_VssEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTSI2SD_VsdEqR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTTSD2SI_GqWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTTSS2SI_GqWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTSD2SI_GqWsdR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE CVTSS2SI_GqWssR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE PEXTRQ_EqVdqIbR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE PEXTRQ_EqVdqIbM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#endif  // #if BX_SUPPORT_X86_64

  BX_SMF BX_INSF_TYPE RDTSCP(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE INVLPG(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RSM(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE WRMSR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RDTSC(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RDPMC(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE RDMSR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SYSENTER(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE SYSEXIT(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE MONITOR(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE MWAIT(bxInstruction_c *) BX_CPP_AttrRegparmN(1);

  BX_SMF BX_INSF_TYPE UndefinedOpcode(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BxError(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_HANDLERS_CHAINING_SPEEDUPS
  BX_SMF BX_INSF_TYPE BxEndTrace(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#endif

#if BX_CPU_LEVEL >= 6
  BX_SMF BX_INSF_TYPE BxNoSSE(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_AVX
  BX_SMF BX_INSF_TYPE BxNoAVX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#endif
#if BX_SUPPORT_EVEX
  BX_SMF BX_INSF_TYPE BxNoOpMask(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
  BX_SMF BX_INSF_TYPE BxNoEVEX(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#endif
#endif

  BX_CPP_INLINE BX_SMF Bit32u BxResolve32(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#if BX_SUPPORT_X86_64
  BX_CPP_INLINE BX_SMF Bit64u BxResolve64(bxInstruction_c *) BX_CPP_AttrRegparmN(1);
#endif
#if BX_SUPPORT_AVX
  BX_SMF bx_address BxResolveGatherD(bxInstruction_c *, unsigned) BX_CPP_AttrRegparmN(2);
  BX_SMF bx_address BxResolveGatherQ(bxInstruction_c *, unsigned) BX_CPP_AttrRegparmN(2);
#endif
// <TAG-CLASS-CPU-END>

};

// <TAG-DEFINES-DECODE-START>

//
// For decoding...
//

// If the BxImmediate mask is set, the lowest 4 bits of the attribute
// specify which kinds of immediate data required by instruction.

#define BxImmediate         0x000f // bits 3..0: any immediate
#define BxImmediate_I1      0x0001 // imm8 = 1
#define BxImmediate_Ib      0x0002 // 8 bit
#define BxImmediate_Ib_SE   0x0003 // sign extend to operand size
#define BxImmediate_Iw      0x0004 // 16 bit
#define BxImmediate_Id      0x0005 // 32 bit
#define BxImmediate_O       0x0006 // MOV_ALOd, mov_OdAL, mov_eAXOv, mov_OveAX
#if BX_SUPPORT_X86_64
#define BxImmediate_Iq      0x0007 // 64 bit override
#endif
#define BxImmediate_BrOff8  0x0008 // Relative branch offset byte
#define BxImmediate_BrOff16 BxImmediate_Iw // Relative branch offset word, not encodable in 64-bit mode
#define BxImmediate_BrOff32 BxImmediate_Id // Relative branch offset dword

#define BxImmediate_Ib4     BxImmediate_Ib // Register encoded in Ib[7:4]
#define BxImmediate_Ib5     BxImmediate_Ib

// Lookup for opcode and attributes in another opcode tables
// Totally 15 opcode groups supported
#define BxGroupX            0x00f0 // bits 7..4: opcode groups definition
#define BxPrefixSSE66       0x0010 // Group encoding: 0001, SSE_PREFIX_66 only
#define BxPrefixSSEF3       0x0020 // Group encoding: 0010, SSE_PREFIX_F3 only
#define BxPrefixSSEF2       0x0030 // Group encoding: 0011, SSE_PREFIX_F2 only
#define BxPrefixSSE         0x0040 // Group encoding: 0100
#define BxPrefixSSE2        0x0050 // Group encoding: 0101, do not allow SSE_PREFIX_F2 or SSE_PREFIX_F3
#define BxPrefixSSE4        0x0060 // Group encoding: 0110
#define BxPrefixSSEF2F3     0x0070 // Group encoding: 0111, ignore SSE_PREFIX_66
#define BxGroupN            0x0080 // Group encoding: 1000
#define BxSplitGroupN       0x0090 // Group encoding: 1001
#define BxFPEscape          0x00A0 // Group encoding: 1010
#define BxOSizeGrp          0x00B0 // Group encoding: 1011
#define BxSplitMod11B       0x00C0 // Group encoding: 1100
#define BxSplitVexVL        0x00D0 // Group encoding: 1101

// The BxImmediate2 mask specifies kind of second immediate data
// required by instruction.
#define BxImmediate2        0x0300 // bits 8.9: any immediate
#define BxImmediate_Ib2     0x0100
#define BxImmediate_Iw2     0x0200
#define BxImmediate_Id2     0x0300

#define BxVexL0             0x0100 // bit 8 (aliased with imm2)
#define BxVexL1             0x0200 // bit 9 (aliased with imm2)
#define BxVexW0             0x0400 // bit 10
#define BxVexW1             0x0800 // bit 11

#define BxAlias             0x3000 // bits 12..13
#define BxAliasSSE          0x1000 // Encoding 01: form final opcode using SSE prefix and current opcode
#define BxAliasVexW         0x2000 // Encoding 10: form final opcode using VEX.W and current opcode
#define BxAliasVexW64       0x3000 // Encoding 11: form final opcode using VEX.W and current opcode in 64-bit mode only

#define BxLockable          0x4000 // bit 14

#define BxGroup1          BxGroupN
#define BxGroup1A         BxGroupN
#define BxGroup2          BxGroupN
#define BxGroup3          BxGroupN
#define BxGroup4          BxGroupN
#define BxGroup5          BxGroupN
#define BxGroup6          BxGroupN
#define BxGroup7          BxFPEscape
#define BxGroup8          BxGroupN
#define BxGroup9          BxSplitGroupN

#define BxGroup11         BxGroupN
#define BxGroup12         BxGroupN
#define BxGroup13         BxGroupN
#define BxGroup14         BxGroupN
#define BxGroup15         BxSplitGroupN
#define BxGroup16         BxGroupN
#define BxGroup17         BxGroupN
#define BxGroup17A        BxGroupN

#define BxGroupFP         BxSplitGroupN

// <TAG-DEFINES-DECODE-END>

#endif // BX_CPU_H
