#define NEED_CPU_REG_SHORTCUTS 1

#include "config.h"
#undef BX_SUPPORT_AVX // FIXME
#undef BX_SUPPORT_EVEX // FIXME
#define BX_CPP_INLINE inline
#include <stdint.h>
#include <assert.h>

#include "bochs.h"
#include "cpu.h"

#include "simd_int.h"
#include "simd_pfp.h"

#include "dummyfuncs.h"
#include "host_adapter.h"

#include <stdio.h>
#include <mach/mach_time.h>

// protect_ctrl.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::SIDT64_Ms(bxInstruction_c *i)
{
  bx_address eaddr = BX_CPU_RESOLVE_ADDR_64(i);
#if 0
  bx_address laddr = get_laddr64(i->seg(), eaddr);
  host_sidt(laddr);
#else
  write_linear_word(i->seg(), get_laddr64(i->seg(), eaddr), 0);
  write_linear_qword(i->seg(), get_laddr64(i->seg(), (eaddr+2) & i->asize_mask()), 0);
#endif
}

// proc_ctrl.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::NOP(bxInstruction_c *i)
{
  // No operation.
}

// proc_ctrl.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::PAUSE(bxInstruction_c *i)
{
#if BX_SUPPORT_VMX
  if (BX_CPU_THIS_PTR in_vmx_guest)
    VMexit_PAUSE();
#endif

#if BX_SUPPORT_SVM
  if (BX_CPU_THIS_PTR in_svm_guest) {
    if (SVM_INTERCEPT(SVM_INTERCEPT0_PAUSE)) SvmInterceptPAUSE();
  }
#endif
}

// proc_ctrl.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::CPUID(bxInstruction_c *i)
{
  uint32_t eax = EAX, ebx, ecx, edx;
  if (eax > 1) {
    fprintf(stderr, "CPUID(0x%x)", eax);
  }
  assert(eax <= 1);
#if 0
  host_cpuid(&eax, &ebx, &ecx, &edx);
#else
  switch(eax) {
    case 0x00:
      eax = 0xd;
      ebx = 0x756e6547;
      ecx = 0x6c65746e;
      edx = 0x49656e69;
      break;
    case 0x01:
      eax = 0x40651;
      ebx = 0x3100800;
      ecx = 0x7ffafbbf;
      edx = 0xbfebfbff;
      break;
    default:
      assert(false);
  }
#endif

  // clear osxsave flag
  ecx &= ~BX_CPUID_EXT_OSXSAVE;

  RAX = eax;
  RBX = ebx;
  RCX = ecx;
  RDX = edx;
}

// proc_ctrl.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::RDTSC(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 5
#if 0
  if (BX_CPU_THIS_PTR cr4.get_TSD() && CPL != 0) {
    BX_ERROR(("%s: not allowed to use instruction !", i->getIaOpcodeNameShort()));
    exception(BX_GP_EXCEPTION, 0);
  }

#if BX_SUPPORT_VMX
  if (BX_CPU_THIS_PTR in_vmx_guest) {
    if (VMEXIT(VMX_VM_EXEC_CTRL2_RDTSC_VMEXIT)) {
      VMexit(VMX_VMEXIT_RDTSC, 0);
    }
  }
#endif

#if BX_SUPPORT_SVM
  if (BX_CPU_THIS_PTR in_svm_guest)
    if (SVM_INTERCEPT(SVM_INTERCEPT0_RDTSC)) Svm_Vmexit(SVM_VMEXIT_RDTSC);
#endif
#endif

  // return ticks
#if 0
  Bit64u ticks = host_rdtsc();
#else
  Bit64u ticks = mach_absolute_time();
#endif

  RAX = GET32L(ticks);
  RDX = GET32H(ticks);
#endif
}

// stack64.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::PUSH_EqR(bxInstruction_c *i)
{
  push_64(BX_READ_64BIT_REG(i->dst()));
}

// stack64.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::PUSH64_Id(bxInstruction_c *i)
{
  Bit64u imm64 = (Bit32s) i->Id();
  push_64(imm64);
}

// stack64.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::POP_EqR(bxInstruction_c *i)
{
  BX_WRITE_64BIT_REG(i->dst(), pop_64());
}

// stack64.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::LEAVE64(bxInstruction_c *i)
{
  // restore frame pointer
  Bit64u temp64 = stack_read_qword(RBP);
  RSP = RBP + 8;
  RBP = temp64;
}

// flag_ctrl.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::CLD(bxInstruction_c *i)
{
  BX_CPU_THIS_PTR clear_DF();
}

// ctrl_xfer64.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::CALL_Jq(bxInstruction_c *i)
{
  Bit64u new_RIP = RIP + (Bit32s) i->Id();

  /* push 64 bit EA of next instruction */
  stack_write_qword(RSP-8, RIP);

#if 0
  if (! IsCanonical(new_RIP)) {
    BX_ERROR(("%s: canonical RIP violation", i->getIaOpcodeNameShort()));
    exception(BX_GP_EXCEPTION, 0);
  }
#endif

  RIP = new_RIP;
  RSP -= 8;
}

// ctrl_xfer64.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::CALL_EqR(bxInstruction_c *i)
{
  Bit64u new_RIP = BX_READ_64BIT_REG(i->dst());

  /* push 64 bit EA of next instruction */
  stack_write_qword(RSP-8, RIP);

#if 0
  if (! IsCanonical(new_RIP))
  {
    BX_ERROR(("%s: canonical RIP violation", i->getIaOpcodeNameShort()));
    exception(BX_GP_EXCEPTION, 0);
  }
#endif

  RIP = new_RIP;
  RSP -= 8;
}

// ctrl_xfer64.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::JMP_EqR(bxInstruction_c *i)
{
  Bit64u op1_64 = BX_READ_64BIT_REG(i->dst());

#if 0
  if (! IsCanonical(op1_64)) {
    BX_ERROR(("%s: canonical RIP violation", i->getIaOpcodeNameShort()));
    exception(BX_GP_EXCEPTION, 0);
  }
#endif

  RIP = op1_64;
}

// ctrl_xfer64.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::JMP_Jq(bxInstruction_c *i)
{
  Bit64u new_RIP = RIP + (Bit32s) i->Id();

#if 0
  if (! IsCanonical(new_RIP)) {
    BX_ERROR(("%s: canonical RIP violation", i->getIaOpcodeNameShort()));
    exception(BX_GP_EXCEPTION, 0);
  }
#endif

  RIP = new_RIP;
}

// ctrl_xfer64.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::JP_Jq(bxInstruction_c *i)
{
  if (get_PF()) {
    branch_near64(i);
  }
}

// ctrl_xfer64.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::JS_Jq(bxInstruction_c *i)
{
  if (get_SF()) {
    branch_near64(i);
  }
}

// ctrl_xfer64.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::JBE_Jq(bxInstruction_c *i)
{
  if (get_CF() || get_ZF()) {
    branch_near64(i);
  }
}

// ctrl_xfer64.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::JB_Jq(bxInstruction_c *i)
{
  if (get_CF()) {
    branch_near64(i);
  }
}

// ctrl_xfer64.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::JZ_Jq(bxInstruction_c *i)
{
  if (get_ZF()) {
    branch_near64(i);
  }
}

// ctrl_xfer64.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::JNB_Jq(bxInstruction_c *i)
{
  if (! get_CF()) {
    branch_near64(i);
  }
}

// ctrl_xfer64.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::JNS_Jq(bxInstruction_c *i)
{
  if (! get_SF()) {
    branch_near64(i);
  }
}

// ctrl_xfer64.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::JLE_Jq(bxInstruction_c *i)
{
  if (get_ZF() || (getB_SF() != getB_OF())) {
    branch_near64(i);
  }
}

// ctrl_xfer64.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::JNZ_Jq(bxInstruction_c *i)
{
  if (! get_ZF()) {
    branch_near64(i);
  }
}

// ctrl_xfer64.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::JNL_Jq(bxInstruction_c *i)
{
  if (getB_SF() == getB_OF()) {
    branch_near64(i);
  }
}

// ctrl_xfer64.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::JNBE_Jq(bxInstruction_c *i)
{
  if (! (get_CF() || get_ZF())) {
    branch_near64(i);
  }
}

// ctrl_xfer64.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::JNLE_Jq(bxInstruction_c *i)
{
  if (! get_ZF() && (getB_SF() == getB_OF())) {
    branch_near64(i);
  }
}

// ctrl_xfer64.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::JL_Jq(bxInstruction_c *i)
{
  if (getB_SF() != getB_OF()) {
    branch_near64(i);
  }
}

// ctrl_xfer64.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::RETnear64(bxInstruction_c *i)
{
  Bit64u return_RIP = stack_read_qword(RSP);

#if 0
  if (! IsCanonical(return_RIP)) {
    BX_ERROR(("%s: canonical RIP violation", i->getIaOpcodeNameShort()));
    exception(BX_GP_EXCEPTION, 0);
  }
#endif

  RIP = return_RIP;
  RSP += 8;
}

// string.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::REP_MOVSB_YbXb(bxInstruction_c *i)
{
#if BX_SUPPORT_X86_64
  if (i->as64L())
    BX_CPU_THIS_PTR repeat(i, &BX_CPU_C::MOVSB64_YbXb);
  else
#endif
  if (i->as32L()) {
    assert(false);
  } else {
    assert(false);
  }
}

// string.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::REP_MOVSQ_YqXq(bxInstruction_c *i)
{
  if (i->as64L()) {
    BX_CPU_THIS_PTR repeat(i, &BX_CPU_C::MOVSQ64_YqXq);
  }
  else {
    BX_CPU_THIS_PTR repeat(i, &BX_CPU_C::MOVSQ32_YqXq);
    BX_CLEAR_64BIT_HIGH(BX_64BIT_REG_RSI); // always clear upper part of RSI/RDI
    BX_CLEAR_64BIT_HIGH(BX_64BIT_REG_RDI);
  }
}

// string.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::MOVSB64_YbXb(bxInstruction_c *i)
{
  Bit8u temp8;

  Bit64u rsi = RSI;
  Bit64u rdi = RDI;

  temp8 = read_linear_byte(i->seg(), get_laddr64(i->seg(), rsi));
  write_linear_byte(BX_SEG_REG_ES, rdi, temp8);

  if (BX_CPU_THIS_PTR get_DF()) {
    /* decrement RSI, RDI */
    rsi--;
    rdi--;
  }
  else {
    /* increment RSI, RDI */
    rsi++;
    rdi++;
  }

  RSI = rsi;
  RDI = rdi;
}

// string.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::REP_STOSB_YbAL(bxInstruction_c *i)
{
#if BX_SUPPORT_X86_64
  if (i->as64L())
    BX_CPU_THIS_PTR repeat(i, &BX_CPU_C::STOSB64_YbAL);
  else
#endif
  if (i->as32L()) {
    BX_CPU_THIS_PTR repeat(i, &BX_CPU_C::STOSB32_YbAL);
    BX_CLEAR_64BIT_HIGH(BX_64BIT_REG_RDI); // always clear upper part of RDI
  }
  else {
    BX_CPU_THIS_PTR repeat(i, &BX_CPU_C::STOSB16_YbAL);
  }
}

// string.cc
void BX_CPP_AttrRegparmN(1) BX_CPU_C::MOVSQ32_YqXq(bxInstruction_c *i)
{
/* 64 bit opsize mode, 32 bit address size */
  Bit64u temp64;

  Bit32u esi = ESI;
  Bit32u edi = EDI;

  temp64 = read_linear_qword(i->seg(), get_laddr64(i->seg(), esi));
  write_linear_qword(BX_SEG_REG_ES, edi, temp64);

  if (BX_CPU_THIS_PTR get_DF()) {
    esi -= 8;
    edi -= 8;
  }
  else {
    esi += 8;
    edi += 8;
  }

  // zero extension of RSI/RDI
  RSI = esi;
  RDI = edi;
}

// string.cc
void BX_CPP_AttrRegparmN(1) BX_CPU_C::MOVSQ64_YqXq(bxInstruction_c *i)
{
/* 64 bit opsize mode, 64 bit address size */
  Bit64u temp64;

  Bit64u rsi = RSI;
  Bit64u rdi = RDI;

  temp64 = read_linear_qword(i->seg(), get_laddr64(i->seg(), rsi));
  write_linear_qword(BX_SEG_REG_ES, rdi, temp64);

  if (BX_CPU_THIS_PTR get_DF()) {
    rsi -= 8;
    rdi -= 8;
  }
  else {
    rsi += 8;
    rdi += 8;
  }

  RSI = rsi;
  RDI = rdi;
}

// string.cc
void BX_CPP_AttrRegparmN(1) BX_CPU_C::STOSB16_YbAL(bxInstruction_c *i)
{
  Bit16u di = DI;

  write_virtual_byte_32(BX_SEG_REG_ES, di, AL);

  if (BX_CPU_THIS_PTR get_DF()) {
    di--;
  }
  else {
    di++;
  }

  DI = di;
}

// string.cc
void BX_CPP_AttrRegparmN(1) BX_CPU_C::STOSB32_YbAL(bxInstruction_c *i)
{
  Bit32u incr = 1;
  Bit32u edi = EDI;

#if (BX_SUPPORT_REPEAT_SPEEDUPS) && (BX_DEBUGGER == 0)
  /* If conditions are right, we can transfer IO to physical memory
   * in a batch, rather than one instruction at a time.
   */
  if (i->repUsedL() && !BX_CPU_THIS_PTR async_event)
  {
    Bit32u byteCount = FastRepSTOSB(i, BX_SEG_REG_ES, edi, AL, ECX);
    if (byteCount) {
      // Decrement the ticks count by the number of iterations, minus
      // one, since the main cpu loop will decrement one.  Also,
      // the count is predecremented before examined, so defintely
      // don't roll it under zero.
      BX_TICKN(byteCount-1);

      // Decrement eCX.  Note, the main loop will decrement 1 also, so
      // decrement by one less than expected, like the case above.
      RCX = ECX - (byteCount-1);

      incr = byteCount;
    }
    else {
      write_virtual_byte(BX_SEG_REG_ES, edi, AL);
    }
  }
  else
#endif
  {
    write_virtual_byte(BX_SEG_REG_ES, edi, AL);
  }

  if (BX_CPU_THIS_PTR get_DF()) {
    edi -= incr;
  }
  else {
    edi += incr;
  }

  // zero extension of RDI
  RDI = edi;
}

#if BX_SUPPORT_X86_64
// 64 bit address size
void BX_CPP_AttrRegparmN(1) BX_CPU_C::STOSB64_YbAL(bxInstruction_c *i)
{
  Bit64u rdi = RDI;

  write_linear_byte(BX_SEG_REG_ES, rdi, AL);

  if (BX_CPU_THIS_PTR get_DF()) {
    rdi--;
  }
  else {
    rdi++;
  }

  RDI = rdi;
}
#endif

// fpu/fpu.cc
#define CHECK_PENDING_EXCEPTIONS 1
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::FNSTCW(bxInstruction_c *i)
{
  prepareFPU(i, !CHECK_PENDING_EXCEPTIONS);

  Bit16u cwd = BX_CPU_THIS_PTR the_i387.get_control_word();

  bx_address eaddr = BX_CPU_RESOLVE_ADDR(i);

  write_virtual_word(i->seg(), eaddr, cwd);
}

// sse_move.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::MOVAPS_VpsWpsM(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  bx_address eaddr = BX_CPU_RESOLVE_ADDR(i);
  read_virtual_xmmword_aligned(i->seg(), eaddr, &BX_XMM_REG(i->dst()));
#endif
}

// sse_move.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::MOVAPS_WpsVpsM(bxInstruction_c *i)
{
/* MOVAPS:     0F 29 */
/* MOVNTPS:    0F 2B */
/* MOVNTPD: 66 0F 2B */
/* MOVNTDQ: 66 0F E7 */
#if BX_CPU_LEVEL >= 6
  bx_address eaddr = BX_CPU_RESOLVE_ADDR(i);
  write_virtual_xmmword_aligned(i->seg(), eaddr, &BX_XMM_REG(i->src()));
#endif
}

// sse_move.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::MOVAPS_VpsWpsR(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  BX_WRITE_XMM_REG(i->dst(), BX_READ_XMM_REG(i->src()));
#endif
}

// sse_move.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::MOVUPS_VpsWpsM(bxInstruction_c *i)
{
/* MOVUPS:    0F 10 */
/* MOVUPD: 66 0F 10 */
/* MOVDQU: F3 0F 6F */
/* LDDQU:  F2 0F F0 */
#if BX_CPU_LEVEL >= 6
  bx_address eaddr = BX_CPU_RESOLVE_ADDR(i);
  read_virtual_xmmword(i->seg(), eaddr, &BX_XMM_REG(i->dst()));
#endif
}

// sse_move.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::MOVUPS_WpsVpsM(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  bx_address eaddr = BX_CPU_RESOLVE_ADDR(i);
  write_virtual_xmmword(i->seg(), eaddr, &BX_XMM_REG(i->src()));
#endif
}

// sse_move.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::MOVSS_VssWssR(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  /* If the source operand is an XMM register, the high-order
          96 bits of the destination XMM register are not modified. */
  BX_WRITE_XMM_REG_LO_DWORD(i->dst(), BX_READ_XMM_REG_LO_DWORD(i->src()));
#endif
}

// sse_move.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::MOVSS_VssWssM(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  BxPackedXmmRegister op;

  bx_address eaddr = BX_CPU_RESOLVE_ADDR(i);

  /* If the source operand is a memory location, the high-order
          96 bits of the destination XMM register are cleared to 0s */
  op.xmm64u(0) = (Bit64u) read_virtual_dword(i->seg(), eaddr);
  op.xmm64u(1) = 0;

  BX_WRITE_XMM_REGZ(i->dst(), op, i->getVL());
#endif
}

// sse_move.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::MOVSS_WssVssM(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  bx_address eaddr = BX_CPU_RESOLVE_ADDR(i);
  write_virtual_dword(i->seg(), eaddr, BX_READ_XMM_REG_LO_DWORD(i->src()));
#endif
}

// sse_move.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::MOVDDUP_VpdWqR(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  xmm_pbroadcastq(&BX_XMM_REG(i->dst()), BX_READ_XMM_REG_LO_QWORD(i->src()));
#endif
}

// sse_move.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::PMOVMSKB_GdUdq(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  Bit32u mask = xmm_pmovmskb(&BX_XMM_REG(i->src()));
  BX_WRITE_32BIT_REGZ(i->dst(), mask);
#endif
}

// sse_move.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::PALIGNR_VdqWdqIbR(bxInstruction_c *i)
{
  BxPackedXmmRegister op1 = BX_READ_XMM_REG(i->dst()), op2 = BX_READ_XMM_REG(i->src());
  xmm_palignr(&op2, &op1, i->Ib());
  BX_WRITE_XMM_REG(i->dst(), op2);
}

// sse_move.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::MOVD_VdqEdR(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  BxPackedXmmRegister op;
  op.xmm64u(0) = (Bit64u) BX_READ_32BIT_REG(i->src());
  op.xmm64u(1) = 0;

  BX_WRITE_XMM_REGZ(i->dst(), op, i->getVL());
#endif
}

// sse_move.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::MOVD_EdVdR(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  BX_WRITE_32BIT_REGZ(i->dst(), BX_READ_XMM_REG_LO_DWORD(i->src()));
#endif
}

// sse_move.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::MOVQ_VdqEqR(bxInstruction_c *i)
{
  BxPackedXmmRegister op;
  op.xmm64u(0) = BX_READ_64BIT_REG(i->src());
  op.xmm64u(1) = 0;

  BX_WRITE_XMM_REGZ(i->dst(), op, i->getVL());
}

// sse_move.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::MOVQ_EqVqR(bxInstruction_c *i)
{
  BX_WRITE_64BIT_REG(i->dst(), BX_READ_XMM_REG_LO_QWORD(i->src()));
}

// sse_move.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::MOVSD_WsdVsdM(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  bx_address eaddr = BX_CPU_RESOLVE_ADDR(i);
  write_virtual_qword(i->seg(), eaddr, BX_XMM_REG_LO_QWORD(i->src()));
#endif
}

// sse_move.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::MOVSD_VsdWsdR(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  /* If the source operand is an XMM register, the high-order
          64 bits of the destination XMM register are not modified. */
  BX_WRITE_XMM_REG_LO_QWORD(i->dst(), BX_READ_XMM_REG_LO_QWORD(i->src()));
#endif
}

// sse_move.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::MOVSD_VsdWsdM(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  BxPackedXmmRegister op;
  bx_address eaddr = BX_CPU_RESOLVE_ADDR(i);
  op.xmm64u(0) = read_virtual_qword(i->seg(), eaddr);
  op.xmm64u(1) = 0; /* zero-extension to 128 bit */

  BX_WRITE_XMM_REGZ(i->dst(), op, i->getVL());
#endif
}

// sse_move.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::MOVHLPS_VpsWpsR(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  BX_WRITE_XMM_REG_LO_QWORD(i->dst(), BX_READ_XMM_REG_HI_QWORD(i->src()));
#endif
}

// sse_pfp.cc
#include "fpu/softfloat-compare.h"
static float64_compare_method compare64[8] = {
  float64_eq_ordered_quiet,
  float64_lt_ordered_signalling,
  float64_le_ordered_signalling,
  float64_unordered_quiet,
  float64_neq_unordered_quiet,
  float64_nlt_unordered_signalling,
  float64_nle_unordered_signalling,
  float64_ordered_quiet
};

// sse_pfp.cc
float_status_t mxcsr_to_softfloat_status_word(bx_mxcsr_t mxcsr);
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::CVTSI2SD_VsdEqR(bxInstruction_c *i)
{
  float_status_t status = mxcsr_to_softfloat_status_word(MXCSR);
  float64 result = int64_to_float64(BX_READ_64BIT_REG(i->src()), status);
  check_exceptionsSSE(get_exception_flags(status));
  BX_WRITE_XMM_REG_LO_QWORD(i->dst(), result);
}

// sse_pfp.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::CVTSI2SD_VsdEdR(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  float64 result = int32_to_float64(BX_READ_32BIT_REG(i->src()));
  BX_WRITE_XMM_REG_LO_QWORD(i->dst(), result);
#endif
}

// sse_pfp.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::CVTTSD2SI_GdWsdR(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  float64 op = BX_READ_XMM_REG_LO_QWORD(i->src());

  float_status_t status = mxcsr_to_softfloat_status_word(MXCSR);
  softfloat_status_word_rc_override(status, i);
  Bit32s result = float64_to_int32_round_to_zero(op, status);
  check_exceptionsSSE(get_exception_flags(status));

  BX_WRITE_32BIT_REGZ(i->dst(), (Bit32u) result);
#endif
}

// sse_pfp.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::CVTTSD2SI_GqWsdR(bxInstruction_c *i)
{
  float64 op = BX_READ_XMM_REG_LO_QWORD(i->src());

  float_status_t status = mxcsr_to_softfloat_status_word(MXCSR);
  softfloat_status_word_rc_override(status, i);
  Bit64s result = float64_to_int64_round_to_zero(op, status);
  check_exceptionsSSE(get_exception_flags(status));

  BX_WRITE_64BIT_REG(i->dst(), (Bit64u) result);
}

// sse_pfp.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::CVTTSS2SI_GdWssR(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  float32 op = BX_READ_XMM_REG_LO_DWORD(i->src());

  float_status_t status = mxcsr_to_softfloat_status_word(MXCSR);
  softfloat_status_word_rc_override(status, i);
  Bit32s result = float32_to_int32_round_to_zero(op, status);
  check_exceptionsSSE(get_exception_flags(status));

  BX_WRITE_32BIT_REGZ(i->dst(), (Bit32u) result);
#endif
}

// sse_pfp.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::CVTSI2SS_VssEdR(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  float_status_t status = mxcsr_to_softfloat_status_word(MXCSR);
  float32 result = int32_to_float32(BX_READ_32BIT_REG(i->src()), status);
  check_exceptionsSSE(get_exception_flags(status));
  BX_WRITE_XMM_REG_LO_DWORD(i->dst(), result);
#endif
}

// sse_pfp.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::MINSD_VsdWsdR(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  float64 op1 = BX_READ_XMM_REG_LO_QWORD(i->dst()), op2 = BX_READ_XMM_REG_LO_QWORD(i->src());

  float_status_t status = mxcsr_to_softfloat_status_word(MXCSR);
  op1 = float64_min(op1, op2, status);
  check_exceptionsSSE(get_exception_flags(status));
  BX_WRITE_XMM_REG_LO_QWORD(i->dst(), op1);
#endif
}

// sse_pfp.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::MULSD_VsdWsdR(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  float64 op1 = BX_READ_XMM_REG_LO_QWORD(i->dst()), op2 = BX_READ_XMM_REG_LO_QWORD(i->src());

  float_status_t status = mxcsr_to_softfloat_status_word(MXCSR);
  op1 = float64_mul(op1, op2, status);
  check_exceptionsSSE(get_exception_flags(status));
  BX_WRITE_XMM_REG_LO_QWORD(i->dst(), op1);
#endif
}

// sse_pfp.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::ADDSD_VsdWsdR(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  float64 op1 = BX_READ_XMM_REG_LO_QWORD(i->dst()), op2 = BX_READ_XMM_REG_LO_QWORD(i->src());

  float_status_t status = mxcsr_to_softfloat_status_word(MXCSR);
  op1 = float64_add(op1, op2, status);
  check_exceptionsSSE(get_exception_flags(status));
  BX_WRITE_XMM_REG_LO_QWORD(i->dst(), op1);
#endif
}

// sse_pfp.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::SUBSD_VsdWsdR(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  float64 op1 = BX_READ_XMM_REG_LO_QWORD(i->dst()), op2 = BX_READ_XMM_REG_LO_QWORD(i->src());

  float_status_t status = mxcsr_to_softfloat_status_word(MXCSR);
  op1 = float64_sub(op1, op2, status);
  check_exceptionsSSE(get_exception_flags(status));
  BX_WRITE_XMM_REG_LO_QWORD(i->dst(), op1);
#endif
}

// sse_pfp.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::SUBPD_VpdWpdR(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  BxPackedXmmRegister op1 = BX_READ_XMM_REG(i->dst()), op2 = BX_READ_XMM_REG(i->src());

  float_status_t status = mxcsr_to_softfloat_status_word(MXCSR);
  xmm_subpd(&op1, &op2, status);
  check_exceptionsSSE(get_exception_flags(status));

  BX_WRITE_XMM_REG(i->dst(), op1);
#endif
}

// sse_pfp.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::MULSS_VssWssR(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  float32 op1 = BX_READ_XMM_REG_LO_DWORD(i->dst()), op2 = BX_READ_XMM_REG_LO_DWORD(i->src());

  float_status_t status = mxcsr_to_softfloat_status_word(MXCSR);
  op1 = float32_mul(op1, op2, status);
  check_exceptionsSSE(get_exception_flags(status));
  BX_WRITE_XMM_REG_LO_DWORD(i->dst(), op1);
#endif
}

// sse_pfp.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::DIVSD_VsdWsdR(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  float64 op1 = BX_READ_XMM_REG_LO_QWORD(i->dst()), op2 = BX_READ_XMM_REG_LO_QWORD(i->src());

  float_status_t status = mxcsr_to_softfloat_status_word(MXCSR);
  op1 = float64_div(op1, op2, status);
  check_exceptionsSSE(get_exception_flags(status));
  BX_WRITE_XMM_REG_LO_QWORD(i->dst(), op1);
#endif
}

// sse_pfp.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::UCOMISD_VsdWsdR(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  float64 op1 = BX_READ_XMM_REG_LO_QWORD(i->dst()), op2 = BX_READ_XMM_REG_LO_QWORD(i->src());

  float_status_t status = mxcsr_to_softfloat_status_word(MXCSR);
  softfloat_status_word_rc_override(status, i);
  int rc = float64_compare_quiet(op1, op2, status);
  check_exceptionsSSE(get_exception_flags(status));
  BX_CPU_THIS_PTR write_eflags_fpu_compare(rc);
#endif
}

// sse_pfp.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::UCOMISS_VssWssR(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  float32 op1 = BX_READ_XMM_REG_LO_DWORD(i->dst()), op2 = BX_READ_XMM_REG_LO_DWORD(i->src());

  float_status_t status = mxcsr_to_softfloat_status_word(MXCSR);
  softfloat_status_word_rc_override(status, i);
  int rc = float32_compare_quiet(op1, op2, status);
  check_exceptionsSSE(get_exception_flags(status));
  BX_CPU_THIS_PTR write_eflags_fpu_compare(rc);
#endif
}

// sse_pfp.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::MAXSD_VsdWsdR(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  float64 op1 = BX_READ_XMM_REG_LO_QWORD(i->dst()), op2 = BX_READ_XMM_REG_LO_QWORD(i->src());

  float_status_t status = mxcsr_to_softfloat_status_word(MXCSR);
  op1 = float64_max(op1, op2, status);
  check_exceptionsSSE(get_exception_flags(status));
  BX_WRITE_XMM_REG_LO_QWORD(i->dst(), op1);
#endif
}

// sse_pfp.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::CMPSD_VsdWsdIbR(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  float64 op1 = BX_READ_XMM_REG_LO_QWORD(i->dst()), op2 = BX_READ_XMM_REG_LO_QWORD(i->src());

  float_status_t status = mxcsr_to_softfloat_status_word(MXCSR);
  int ib = i->Ib() & 7;

  if(compare64[ib](op1, op2, status)) {
    op1 = BX_CONST64(0xFFFFFFFFFFFFFFFF);
  } else {
    op1 = 0;
  }

  check_exceptionsSSE(get_exception_flags(status));
  BX_WRITE_XMM_REG_LO_QWORD(i->dst(), op1);
#endif
}

// sse_pfp.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::ROUNDSD_VsdWsdIbR(bxInstruction_c *i)
{
  float64 op = BX_READ_XMM_REG_LO_QWORD(i->src());

  float_status_t status = mxcsr_to_softfloat_status_word(MXCSR);
  Bit8u control = i->Ib();

  // override MXCSR rounding mode with control coming from imm8
  if ((control & 0x4) == 0)
    status.float_rounding_mode = control & 0x3;
  // ignore precision exception result
  if (control & 0x8)
    status.float_suppress_exception |= float_flag_inexact;

  op = float64_round_to_int(op, status);

  check_exceptionsSSE(get_exception_flags(status));
  BX_WRITE_XMM_REG_LO_QWORD(i->dst(), op);
}

// sse_pfp.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::HADDPD_VpdWpdR(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  BxPackedXmmRegister op1 = BX_READ_XMM_REG(i->dst()), op2 = BX_READ_XMM_REG(i->src());

  float_status_t status = mxcsr_to_softfloat_status_word(MXCSR);
  xmm_haddpd(&op1, &op2, status);
  check_exceptionsSSE(get_exception_flags(status));

  BX_WRITE_XMM_REG(i->dst(), op1);
#endif
}

// fpu/fpu_load_store.cc
float_status_t i387cw_to_softfloat_status_word(Bit16u control_word);
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::FLD_DOUBLE_REAL(bxInstruction_c *i)
{
  BX_CPU_THIS_PTR prepareFPU(i);

  RMAddr(i) = BX_CPU_RESOLVE_ADDR(i);
  float64 load_reg = read_virtual_qword(i->seg(), RMAddr(i));

  FPU_update_last_instruction(i);

  clear_C1();

  if (! IS_TAG_EMPTY(-1)) {
    FPU_stack_overflow();
    BX_NEXT_INSTR(i);
  }

  float_status_t status =
    i387cw_to_softfloat_status_word(BX_CPU_THIS_PTR the_i387.get_control_word());

  // convert to floatx80 format
  floatx80 result = float64_to_floatx80(load_reg, status);

  unsigned unmasked = FPU_exception(status.float_exception_flags);
  if (! (unmasked & FPU_CW_Invalid)) {
    BX_CPU_THIS_PTR the_i387.FPU_push();
    BX_WRITE_FPU_REG(result, 0);
  }

  BX_NEXT_INSTR(i);
}

// xsave.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::XSAVE(bxInstruction_c *i)
{
#define XSAVEC_COMPACTION_ENABLED BX_CONST64(0x8000000000000000)
#if BX_CPU_LEVEL >= 6
  //BX_CPU_THIS_PTR prepareXSAVE();

  //BX_DEBUG(("%s: save processor state XCR0=0x%08x", i->getIaOpcodeNameShort(), BX_CPU_THIS_PTR xcr0.get32()));

  bx_address eaddr = BX_CPU_RESOLVE_ADDR(i);

#if 0
#if BX_SUPPORT_ALIGNMENT_CHECK && BX_CPU_LEVEL >= 4
  if (BX_CPU_THIS_PTR alignment_check()) {
    if (laddr & 0x3) {
      BX_ERROR(("%s: access not aligned to 4-byte cause model specific #AC(0)", i->getIaOpcodeNameShort()));
      exception(BX_AC_EXCEPTION, 0);
    }
  }
#endif
#endif

  if (eaddr & 0x3f) {
    assert(false);
  }

  bx_address asize_mask = i->asize_mask();

  //
  // We will go feature-by-feature and not run over all XCR0 bits
  //

  Bit64u xstate_bv = read_virtual_qword(i->seg(), (eaddr + 512) & asize_mask);

  Bit32u requested_feature_bitmap = BX_CPU_THIS_PTR xcr0.get32() & EAX;
  Bit32u xinuse = get_xinuse_vector(requested_feature_bitmap);

  bx_bool xsaveopt = (i->getIaOpcode() == BX_IA_XSAVEOPT);

  /////////////////////////////////////////////////////////////////////////////
  if ((requested_feature_bitmap & BX_XCR0_FPU_MASK) != 0)
  {
    if (! xsaveopt || (xinuse & BX_XCR0_FPU_MASK) != 0) {
      // TODO
      //xsave_x87_state(i, eaddr);
    }

    if (xinuse & BX_XCR0_FPU_MASK)
      xstate_bv |=  BX_XCR0_FPU_MASK;
    else
      xstate_bv &= ~BX_XCR0_FPU_MASK;
  }

  /////////////////////////////////////////////////////////////////////////////
  if ((requested_feature_bitmap & (BX_XCR0_SSE_MASK | BX_XCR0_YMM_MASK)) != 0)
  {
    assert(false);
  }

  /////////////////////////////////////////////////////////////////////////////
  if ((requested_feature_bitmap & BX_XCR0_SSE_MASK) != 0)
  {
    assert(false);
  }

#if BX_SUPPORT_AVX
  if ((requested_feature_bitmap & BX_XCR0_YMM_MASK) != 0)
  {
    assert(false);
  }
#endif

#if BX_SUPPORT_EVEX
  if ((requested_feature_bitmap & BX_XCR0_OPMASK_MASK) != 0)
  {
    assert(false);
  }

  if ((requested_feature_bitmap & BX_XCR0_ZMM_HI256_MASK) != 0)
  {
    assert(false);
  }

  if ((requested_feature_bitmap & BX_XCR0_HI_ZMM_MASK) != 0)
  {
    assert(false);
  }
#endif

  // always update header to 'dirty' state
  write_virtual_qword(i->seg(), (eaddr + 512) & asize_mask, xstate_bv);
#endif
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::XRSTOR(bxInstruction_c *i)
{
  //BX_CPU_THIS_PTR prepareXSAVE();

  bx_address eaddr = BX_CPU_RESOLVE_ADDR(i);

#if 0
#if BX_SUPPORT_ALIGNMENT_CHECK && BX_CPU_LEVEL >= 4
  if (BX_CPU_THIS_PTR alignment_check()) {
    if (laddr & 0x3) {
      BX_ERROR(("XRSTOR: access not aligned to 4-byte cause model specific #AC(0)"));
      exception(BX_AC_EXCEPTION, 0);
    }
  }
#endif
#endif

  if (eaddr & 0x3f) {
    assert(false);
  }

  bx_address asize_mask = i->asize_mask();

  Bit64u xstate_bv = read_virtual_qword(i->seg(), (eaddr + 512) & asize_mask);
  Bit64u xcomp_bv = read_virtual_qword(i->seg(), (eaddr + 520) & asize_mask);
  Bit64u header3 = read_virtual_qword(i->seg(), (eaddr + 528) & asize_mask);

  if (header3 != 0) {
    assert(false);
  }

  bx_bool compaction = (xcomp_bv & XSAVEC_COMPACTION_ENABLED) != 0;

  if (! BX_CPUID_SUPPORT_ISA_EXTENSION(BX_ISA_XSAVEC) || ! compaction) {
    if (xcomp_bv != 0) {
      assert(false);
    }
  }

  if (! compaction) {
    if ((~BX_CPU_THIS_PTR xcr0.get32() & xstate_bv) != 0 || (GET32H(xstate_bv) << 1) != 0) {
      assert(false);
    }
  }
  else {
    if ((~BX_CPU_THIS_PTR xcr0.get32() & xcomp_bv) != 0 || (GET32H(xcomp_bv) << 1) != 0) {
      assert(false);
    }

    if (xstate_bv & ~xcomp_bv) {
      assert(false);
    }

    Bit64u header4 = read_virtual_qword(i->seg(), (eaddr + 536) & asize_mask);
    Bit64u header5 = read_virtual_qword(i->seg(), (eaddr + 544) & asize_mask);
    Bit64u header6 = read_virtual_qword(i->seg(), (eaddr + 552) & asize_mask);
    Bit64u header7 = read_virtual_qword(i->seg(), (eaddr + 560) & asize_mask);
    Bit64u header8 = read_virtual_qword(i->seg(), (eaddr + 568) & asize_mask);

    if (header4 | header5 | header6 | header7 | header8) {
      assert(false);
    }
  }

  //
  // We will go feature-by-feature and not run over all XCR0 bits
  //

  Bit32u requested_feature_bitmap = BX_CPU_THIS_PTR xcr0.get32() & EAX;

  /////////////////////////////////////////////////////////////////////////////
  if ((requested_feature_bitmap & BX_XCR0_FPU_MASK) != 0)
  {
    // TODO
#if 0
    if (xstate_bv & BX_XCR0_FPU_MASK) {
      xrstor_x87_state(i, eaddr);
    } else {
      xrstor_init_x87_state();
    }
#endif
  }

  /////////////////////////////////////////////////////////////////////////////
  if ((requested_feature_bitmap & BX_XCR0_SSE_MASK) != 0 || 
     ((requested_feature_bitmap & BX_XCR0_YMM_MASK) != 0 && ! compaction))
  {
    assert(false);
  }

  /////////////////////////////////////////////////////////////////////////////
  if ((requested_feature_bitmap & BX_XCR0_SSE_MASK) != 0)
  {
    assert(false);
  }

  if (compaction) {
    Bit32u offset = XSAVE_YMM_STATE_OFFSET;

#if BX_SUPPORT_AVX
    /////////////////////////////////////////////////////////////////////////////
    if ((requested_feature_bitmap & BX_XCR0_YMM_MASK) != 0)
    {
      assert(false);
    }
#endif

#if BX_SUPPORT_EVEX
    /////////////////////////////////////////////////////////////////////////////
    if ((requested_feature_bitmap & BX_XCR0_OPMASK_MASK) != 0)
    {
      if (xstate_bv & BX_XCR0_OPMASK_MASK)
        xrstor_opmask_state(i, eaddr+offset);
      else
        xrstor_init_opmask_state();

      offset += XSAVE_OPMASK_STATE_LEN;
    }

    /////////////////////////////////////////////////////////////////////////////
    if ((requested_feature_bitmap & BX_XCR0_ZMM_HI256_MASK) != 0)
    {
      if (xstate_bv & BX_XCR0_ZMM_HI256_MASK)
        xrstor_zmm_hi256_state(i, eaddr+offset);
      else
        xrstor_init_zmm_hi256_state();

      offset += XSAVE_ZMM_HI256_STATE_LEN;
    }

    /////////////////////////////////////////////////////////////////////////////
    if ((requested_feature_bitmap & BX_XCR0_HI_ZMM_MASK) != 0)
    {
      if (xstate_bv & BX_XCR0_HI_ZMM_MASK)
        xrstor_hi_zmm_state(i, eaddr+offset);
      else
        xrstor_init_hi_zmm_state();

      offset += XSAVE_HI_ZMM_STATE_LEN;
    }
#endif
  }
  else {
#if BX_SUPPORT_AVX
    /////////////////////////////////////////////////////////////////////////////
    if ((requested_feature_bitmap & BX_XCR0_YMM_MASK) != 0)
    {
      assert(false);
    }
#endif

#if BX_SUPPORT_EVEX
    /////////////////////////////////////////////////////////////////////////////
    if ((requested_feature_bitmap & BX_XCR0_OPMASK_MASK) != 0)
    {
      if (xstate_bv & BX_XCR0_OPMASK_MASK)
        xrstor_opmask_state(i, eaddr+XSAVE_OPMASK_STATE_OFFSET);
      else
        xrstor_init_opmask_state();
    }

    /////////////////////////////////////////////////////////////////////////////
    if ((requested_feature_bitmap & BX_XCR0_ZMM_HI256_MASK) != 0)
    {
      if (xstate_bv & BX_XCR0_ZMM_HI256_MASK)
        xrstor_zmm_hi256_state(i, eaddr+XSAVE_ZMM_HI256_STATE_OFFSET);
      else
        xrstor_init_zmm_hi256_state();
    }

    /////////////////////////////////////////////////////////////////////////////
    if ((requested_feature_bitmap & BX_XCR0_HI_ZMM_MASK) != 0)
    {
      if (xstate_bv & BX_XCR0_HI_ZMM_MASK)
        xrstor_hi_zmm_state(i, eaddr+XSAVE_HI_ZMM_STATE_OFFSET);
      else
        xrstor_init_hi_zmm_state();
    }
#endif
  }
}
