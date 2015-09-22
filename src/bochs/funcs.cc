#define NEED_CPU_REG_SHORTCUTS 1

#include <config.h>
#undef BX_SUPPORT_AVX // FIXME
#undef BX_SUPPORT_EVEX // FIXME
#define BX_CPP_INLINE inline
#include <stdint.h>
#include <assert.h>

#include <bochs.h>
#include <cpu.h>

#include "simd_int.h"

#include "dummyfuncs.h"

// proc_ctrl.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::NOP(bxInstruction_c *i)
{
  // No operation.
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

// load.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::LOAD_Eq(bxInstruction_c *i)
{
  bx_address eaddr = BX_CPU_RESOLVE_ADDR_64(i);
  TMP64 = read_linear_qword(i->seg(), get_laddr64(i->seg(), eaddr));
  BX_CPU_CALL_METHOD(i->execute2(), (i));
}

// load.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::LOAD_Wdq(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  bx_address eaddr = BX_CPU_RESOLVE_ADDR(i);

  if (BX_CPU_THIS_PTR mxcsr.get_MM())
    read_virtual_xmmword(i->seg(), eaddr, &BX_READ_XMM_REG(BX_TMP_REGISTER));
  else
    read_virtual_xmmword_aligned(i->seg(), eaddr, &BX_READ_XMM_REG(BX_VECTOR_TMP_REGISTER));

  BX_CPU_CALL_METHOD(i->execute2(), (i));
#endif
}

// bit.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::SETZ_EbR(bxInstruction_c *i)
{
  BX_WRITE_8BIT_REGx(i->dst(), i->extend8bitL(), getB_ZF());
}

// bit.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::SETNZ_EbM(bxInstruction_c *i)
{
  bx_address eaddr = BX_CPU_RESOLVE_ADDR(i);
  Bit8u result_8 = !getB_ZF();
  *((Bit8u*)eaddr) = result_8;
}

// bits.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::SETNZ_EbR(bxInstruction_c *i)
{
  BX_WRITE_8BIT_REGx(i->dst(), i->extend8bitL(), !getB_ZF());
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
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::PMOVMSKB_GdUdq(bxInstruction_c *i)
{
#if BX_CPU_LEVEL >= 6
  Bit32u mask = xmm_pmovmskb(&BX_XMM_REG(i->src()));
  BX_WRITE_32BIT_REGZ(i->dst(), mask);
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
      if (xstate_bv & BX_XCR0_YMM_MASK)
        xrstor_ymm_state(i, eaddr+offset);
      else
        xrstor_init_ymm_state();

      offset += XSAVE_YMM_STATE_LEN;
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
      if (xstate_bv & BX_XCR0_YMM_MASK)
        xrstor_ymm_state(i, eaddr+XSAVE_YMM_STATE_OFFSET);
      else
        xrstor_init_ymm_state();
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
