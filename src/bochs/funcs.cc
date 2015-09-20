#define NEED_CPU_REG_SHORTCUTS 1

#include <config.h>
#undef BX_SUPPORT_AVX // FIXME
#undef BX_SUPPORT_EVEX // FIXME
#define BX_CPP_INLINE inline
#include <stdint.h>
#include <assert.h>

#include <bochs.h>
#include <cpu.h>

#include "dummyfuncs.h"

// stack64.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::PUSH_EqR(bxInstruction_c *i)
{
  push_64(BX_READ_64BIT_REG(i->dst()));
}

// data_xfer8.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::MOV_EbIbR(bxInstruction_c *i)
{
  BX_WRITE_8BIT_REGx(i->dst(), i->extend8bitL(), i->Ib());
}

// data_xfer32.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::MOV_EdIdR(bxInstruction_c *i)
{
  BX_WRITE_32BIT_REGZ(i->dst(), i->Id());
}

// data_xfer32.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::MOV_EdIdM(bxInstruction_c *i)
{
  bx_address eaddr = BX_CPU_RESOLVE_ADDR(i);
  WriteHostQWordToLittleEndian((Bit64u*)eaddr, i->Id());
}

// data_xfer64.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::MOV_GqEqR(bxInstruction_c *i)
{
  BX_WRITE_64BIT_REG(i->dst(), BX_READ_64BIT_REG(i->src()));
}

// data_xfer64.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::LEA_GqM(bxInstruction_c *i)
{
  bx_address eaddr = BX_CPU_RESOLVE_ADDR_64(i);
  BX_WRITE_64BIT_REG(i->dst(), eaddr);
}

// arith64.cc
BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::SUB_EqIdR(bxInstruction_c *i)
{
  Bit64u op1_64, op2_64, diff_64;

  op1_64 = BX_READ_64BIT_REG(i->dst());
  op2_64 = (Bit32s) i->Id();
  diff_64 = op1_64 - op2_64;
  BX_WRITE_64BIT_REG(i->dst(), diff_64);

  SET_FLAGS_OSZAPC_SUB_64(op1_64, op2_64, diff_64);
}
