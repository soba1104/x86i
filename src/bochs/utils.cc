// funcs の実装に必要な関数群を実装したファイル
// stack.h, stack.cc などに含まれる関数群を実装

#define NEED_CPU_REG_SHORTCUTS 1

#include <config.h>
#undef BX_SUPPORT_AVX // FIXME
#undef BX_SUPPORT_EVEX // FIXME
#define BX_CPP_INLINE inline
#include <stdint.h>
#include <assert.h>

#include <bochs.h>
#include <cpu.h>

extern "C" {

void *alloc_cpu()
{
  return new BX_CPU_C();
}

void set_stack(void *cpu, void *stack)
{
  ((BX_CPU_C*)cpu)->set_stack(stack);
}

void set_ip(void *cpu, uint64_t ip)
{
  ((BX_CPU_C*)cpu)->set_ip(ip);
}

uint64_t get_ip(void *cpu)
{
  return ((BX_CPU_C*)cpu)->get_ip();
}

void free_cpu(void *cpu)
{
  delete ((BX_CPU_C*)cpu);
}

int decode64(void *cpu, void *insn) {
  bxInstruction_c *i = (bxInstruction_c*)insn;
  return ((BX_CPU_C*)cpu)->decode64(i);
}

void step(void *cpu, void *insn) {
  BX_CPU_C *c = (BX_CPU_C*)cpu;
  bxInstruction_c *i = (bxInstruction_c*)insn;
  (c->*(i->execute1))(i);
}

}

BX_CPU_C::BX_CPU_C(unsigned id): bx_cpuid(id)
{
  memset(gen_reg, 0, sizeof(gen_reg));
}

BX_CPU_C::~BX_CPU_C()
{
}

void BX_CPU_C::set_stack(void *stack)
{
  RSP = (Bit64u)stack;
}

void BX_CPU_C::set_ip(Bit64u ip)
{
  RIP = ip;
}

Bit64u BX_CPU_C::get_ip(void)
{
  return RIP;
}

void BX_CPP_AttrRegparmN(2) BX_CPU_C::stack_write_qword(bx_address offset, Bit64u data)
{
  WriteHostQWordToLittleEndian((Bit64u*)offset, data);
}

Bit64u BX_CPP_AttrRegparmN(1) BX_CPU_C::stack_read_qword(bx_address offset)
{
  Bit64u data;
  ReadHostQWordFromLittleEndian((Bit64u*)offset, data);
  return data;
}

/* push 64 bit operand */
void BX_CPP_AttrRegparmN(1) BX_CPU_C::push_64(Bit64u value64)
{
  /* StackAddrSize = 64 */
  stack_write_qword(RSP-8, value64);
  RSP -= 8;
}

/* pop 64 bit operand from the stack */
Bit64u BX_CPU_C::pop_64(void)
{
  /* StackAddrSize = 64 */
  Bit64u value64 = stack_read_qword(RSP);
  RSP += 8;

  return value64;
}
