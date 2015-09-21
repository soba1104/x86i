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

const char *get_opcode_name(void *insn) {
  bxInstruction_c *i = (bxInstruction_c*)insn;
  return get_bx_opcode_name(i->getIaOpcode());
}

}

const char *get_bx_opcode_name(Bit16u ia_opcode)
{
  static const char* BxOpcodeNamesTable[BX_IA_LAST] =
  {
#define bx_define_opcode(a, b, c, d, s1, s2, s3, s4, e) #a,
#include "ia_opcodes.h"
  };
#undef  bx_define_opcode

  return (ia_opcode < BX_IA_LAST) ? BxOpcodeNamesTable[ia_opcode] : 0;
}

BX_CPU_C::BX_CPU_C(unsigned id): bx_cpuid(id)
{
  unsigned n;

  memset(gen_reg, 0, sizeof(gen_reg));

  BX_CPU_THIS_PTR cpu_mode = BX_MODE_LONG_64; // FIXME

//init.cc のオリジナルのコンストラクタから持ってきたもの
  for (unsigned n=0;n<BX_ISA_EXTENSIONS_ARRAY_SIZE;n++)
    ia_extensions_bitmask[n] = 0;

  ia_extensions_bitmask[0] = (1 << BX_ISA_386);
  if (BX_SUPPORT_FPU)
    ia_extensions_bitmask[0] |= (1 << BX_ISA_X87);

#if BX_SUPPORT_VMX
  vmx_extensions_bitmask = 0;
#endif
#if BX_SUPPORT_SVM
  svm_extensions_bitmask = 0;
#endif

//init.cc:reset から持ってきたもの
#if BX_CPU_LEVEL >= 6
  BX_CPU_THIS_PTR xcr0.set32(0x1);
  BX_CPU_THIS_PTR xcr0_suppmask = 0x3;
#if BX_SUPPORT_AVX
  if (BX_CPUID_SUPPORT_ISA_EXTENSION(BX_ISA_AVX))
    BX_CPU_THIS_PTR xcr0_suppmask |= BX_XCR0_YMM_MASK;
#if BX_SUPPORT_EVEX
  if (BX_CPUID_SUPPORT_ISA_EXTENSION(BX_ISA_AVX512))
    BX_CPU_THIS_PTR xcr0_suppmask |= BX_XCR0_OPMASK_MASK | BX_XCR0_ZMM_HI256_MASK | BX_XCR0_HI_ZMM_MASK;
#endif
#endif // BX_SUPPORT_AVX
#endif // BX_CPU_LEVEL >= 6

#if BX_SUPPORT_FPU
  //if (source == BX_RESET_HARDWARE) {
    BX_CPU_THIS_PTR the_i387.reset();
  //}
#endif

#if BX_CPU_LEVEL >= 6
  BX_CPU_THIS_PTR sse_ok = 0;
#if BX_SUPPORT_AVX
  BX_CPU_THIS_PTR avx_ok = 0;
#endif

#if BX_SUPPORT_EVEX
  BX_CPU_THIS_PTR opmask_ok = BX_CPU_THIS_PTR evex_ok = 0;

  for (n=0; n<8; n++)
    BX_WRITE_OPMASK(n, 0);
#endif

  // Reset XMM state - unchanged on #INIT
  //if (source == BX_RESET_HARDWARE) {
    for(n=0; n<BX_XMM_REGISTERS; n++) {
      BX_CLEAR_AVX_REG(n);
    }

    BX_CPU_THIS_PTR mxcsr.mxcsr = MXCSR_RESET;
    BX_CPU_THIS_PTR mxcsr_mask = 0x0000ffbf;
    if (BX_CPUID_SUPPORT_ISA_EXTENSION(BX_ISA_SSE2))
      BX_CPU_THIS_PTR mxcsr_mask |= MXCSR_DAZ;
    if (BX_CPUID_SUPPORT_ISA_EXTENSION(BX_ISA_MISALIGNED_SSE))
      BX_CPU_THIS_PTR mxcsr_mask |= MXCSR_MISALIGNED_EXCEPTION_MASK;
  //}
#endif
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

void BX_CPP_AttrRegparmN(1) BX_CPU_C::branch_near64(bxInstruction_c *i)
{
  Bit64u new_RIP = RIP + (Bit32s) i->Id();

#if 0
  if (! IsCanonical(new_RIP)) {
    BX_ERROR(("branch_near64: canonical RIP violation"));
    exception(BX_GP_EXCEPTION, 0);
  }
#endif

  RIP = new_RIP;

#if 0
#if BX_SUPPORT_HANDLERS_CHAINING_SPEEDUPS == 0
  // assert magic async_event to stop trace execution
  BX_CPU_THIS_PTR async_event |= BX_ASYNC_EVENT_STOP_TRACE;
#endif
#endif
}

// xsave 関連
bx_bool BX_CPU_C::xsave_x87_state_xinuse(void)
{
  if (BX_CPU_THIS_PTR the_i387.get_control_word() != 0x037F ||
      BX_CPU_THIS_PTR the_i387.get_status_word() != 0 ||
      BX_CPU_THIS_PTR the_i387.get_tag_word() != 0xFFFF ||
      BX_CPU_THIS_PTR the_i387.foo != 0 ||
      BX_CPU_THIS_PTR the_i387.fip != 0 || BX_CPU_THIS_PTR the_i387.fcs != 0 ||
      BX_CPU_THIS_PTR the_i387.fdp != 0 || BX_CPU_THIS_PTR the_i387.fds != 0) return BX_TRUE;

  for (unsigned index=0;index<8;index++) {
    floatx80 reg = BX_FPU_REG(index);
    if (reg.exp != 0 || reg.fraction != 0) return BX_TRUE;
  }

  return BX_FALSE;
}

bx_bool BX_CPU_C::xsave_sse_state_xinuse(void)
{
  for(unsigned index=0; index < 16; index++) {
    // set XMM8-XMM15 only in 64-bit mode
    if (index < 8 || long64_mode()) {
      const BxPackedXmmRegister *reg = &BX_XMM_REG(index);
      if (! is_clear(reg)) return BX_TRUE;
    }
  }

  return BX_FALSE;
}
