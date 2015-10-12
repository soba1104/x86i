// funcs の実装に必要な関数群を実装したファイル
// stack.h, stack.cc などに含まれる関数群を実装

#define NEED_CPU_REG_SHORTCUTS 1

#include "config.h"
#undef BX_SUPPORT_AVX // FIXME
#undef BX_SUPPORT_EVEX // FIXME
#define BX_CPP_INLINE inline
#include <stdint.h>
#include <assert.h>

#include "bochs.h"
#include "cpu.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" {

void *alloc_cpu()
{
  return new BX_CPU_C();
}

void set_stack(void *cpu, void *stack)
{
  ((BX_CPU_C*)cpu)->set_stack(stack);
}

void set_rip(void *cpu, uint64_t rip) { ((BX_CPU_C*)cpu)->set_rip(rip); }
void set_rax(void *cpu, uint64_t rax) { ((BX_CPU_C*)cpu)->set_rax(rax); }
void set_rdi(void *cpu, uint64_t rdi) { ((BX_CPU_C*)cpu)->set_rdi(rdi); }
void set_rsi(void *cpu, uint64_t rsi) { ((BX_CPU_C*)cpu)->set_rsi(rsi); }
void set_rdx(void *cpu, uint64_t rdx) { ((BX_CPU_C*)cpu)->set_rdx(rdx); }
void set_rcx(void *cpu, uint64_t rcx) { ((BX_CPU_C*)cpu)->set_rcx(rcx); }
void set_r8(void *cpu,  uint64_t r8)  { ((BX_CPU_C*)cpu)->set_r8(r8); }
void set_r9(void *cpu,  uint64_t r9)  { ((BX_CPU_C*)cpu)->set_r9(r9); }
void set_r10(void *cpu,  uint64_t r9) { ((BX_CPU_C*)cpu)->set_r10(r9); }
void set_oszapc(void *cpu, uint32_t eflags)  {
  ((BX_CPU_C*)cpu)->setEFlagsOSZAPC(eflags);
}

void set_gs_base(void *cpu, uint64_t base) {
  ((BX_CPU_C*)cpu)->set_gs_base(base);
}

void clear_cf(void *cpu) {
  ((BX_CPU_C*)cpu)->clear_cf();
}

uint64_t get_rip(void *cpu) { return ((BX_CPU_C*)cpu)->get_rip(); }
uint64_t get_rax(void *cpu) { return ((BX_CPU_C*)cpu)->get_rax(); }
uint64_t get_rbx(void *cpu) { return ((BX_CPU_C*)cpu)->get_rbx(); }
uint64_t get_rcx(void *cpu) { return ((BX_CPU_C*)cpu)->get_rcx(); }
uint64_t get_rdx(void *cpu) { return ((BX_CPU_C*)cpu)->get_rdx(); }
uint64_t get_rdi(void *cpu) { return ((BX_CPU_C*)cpu)->get_rdi(); }
uint64_t get_rsi(void *cpu) { return ((BX_CPU_C*)cpu)->get_rsi(); }
uint64_t get_rbp(void *cpu) { return ((BX_CPU_C*)cpu)->get_rbp(); }
uint64_t get_rsp(void *cpu) { return ((BX_CPU_C*)cpu)->get_rsp(); }
uint64_t get_r8(void *cpu)  { return ((BX_CPU_C*)cpu)->get_r8(); }
uint64_t get_r9(void *cpu)  { return ((BX_CPU_C*)cpu)->get_r9(); }
uint64_t get_r10(void *cpu) { return ((BX_CPU_C*)cpu)->get_r10(); }
uint64_t get_r11(void *cpu) { return ((BX_CPU_C*)cpu)->get_r11(); }
uint64_t get_r12(void *cpu) { return ((BX_CPU_C*)cpu)->get_r12(); }
uint64_t get_r13(void *cpu) { return ((BX_CPU_C*)cpu)->get_r13(); }
uint64_t get_r14(void *cpu) { return ((BX_CPU_C*)cpu)->get_r14(); }
uint64_t get_r15(void *cpu) { return ((BX_CPU_C*)cpu)->get_r15(); }
uint64_t get_rflags(void *cpu) { return ((BX_CPU_C*)cpu)->get_eflags(); }

void free_cpu(void *cpu)
{
  delete ((BX_CPU_C*)cpu);
}

int decode64(void *cpu, void *insn) {
  return ((BX_CPU_C*)cpu)->decode64(insn);
}

void step(void *cpu, void *insn) {
  return ((BX_CPU_C*)cpu)->step(insn);
}

uint16_t get_opcode(void *insn) {
  bxInstruction_c *i = (bxInstruction_c*)insn;
  return i->getIaOpcode();
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

  rmw_addr = 0;
  alignment_check_mask = 0;

  memset(gen_reg, 0, sizeof(gen_reg));
  memset(&address_xlation, 0, sizeof(address_xlation));

  BX_CPU_THIS_PTR cpu_mode = BX_MODE_LONG_64; // FIXME

  // 暫定。今の所 segment.base 以外は参照しない。
  BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].cache.u.segment.base = 0;
  BX_CPU_THIS_PTR sregs[BX_SEG_REG_DS].cache.u.segment.base = 0;
  BX_CPU_THIS_PTR sregs[BX_SEG_REG_SS].cache.u.segment.base = 0;
  BX_CPU_THIS_PTR sregs[BX_SEG_REG_ES].cache.u.segment.base = 0;
  BX_CPU_THIS_PTR sregs[BX_SEG_REG_FS].cache.u.segment.base = 0;
  BX_CPU_THIS_PTR sregs[BX_SEG_REG_GS].cache.u.segment.base = 0;

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

  // プロテクトモードの有効化のために  0x00000001
  // 拡張タイプが1で予約されているので 0x00000010
  // ライトスルーを無効化するので      0x20000000
  // キャッシュを無効化するので        0x40000000
  // ページングを有効化するので        0x80000000
  BX_CPU_THIS_PTR cr0.set32(0xe0000011);

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

int BX_CPU_C::decode64(void *insn) {
  bxInstruction_c *i = (bxInstruction_c*)insn;
  Bit8u *iptr = (Bit8u*)RIP;
  int res = fetchDecode64(iptr, 0xffffffff, i, 15);
  RIP += i->ilen();
  return res;
}

void BX_CPU_C::step(void *insn) {
  bxInstruction_c *i = (bxInstruction_c*)insn;
  BX_CPU_CALL_METHOD(i->execute1, (i));
}

void BX_CPU_C::set_stack(void *stack)
{
  RSP = (Bit64u)stack;
}

void BX_CPU_C::set_rip(Bit64u rip) { RIP = rip; }
void BX_CPU_C::set_rax(Bit64u rax) { RAX = rax; }
void BX_CPU_C::set_rdi(Bit64u rdi) { RDI = rdi; }
void BX_CPU_C::set_rsi(Bit64u rsi) { RSI = rsi; }
void BX_CPU_C::set_rdx(Bit64u rdx) { RDX = rdx; }
void BX_CPU_C::set_rcx(Bit64u rcx) { RCX = rcx; }
void BX_CPU_C::set_r8(Bit64u r8)   { R8 = r8; }
void BX_CPU_C::set_r9(Bit64u r9)   { R9 = r9; }
void BX_CPU_C::set_r10(Bit64u r10) { R10 = r10; }

Bit64u BX_CPU_C::get_rip(void) { return RIP; }
Bit64u BX_CPU_C::get_rax(void) { return RAX; }
Bit64u BX_CPU_C::get_rbx(void) { return RBX; }
Bit64u BX_CPU_C::get_rcx(void) { return RCX; }
Bit64u BX_CPU_C::get_rdx(void) { return RDX; }
Bit64u BX_CPU_C::get_rdi(void) { return RDI; }
Bit64u BX_CPU_C::get_rsi(void) { return RSI; }
Bit64u BX_CPU_C::get_rbp(void) { return RBP; }
Bit64u BX_CPU_C::get_rsp(void) { return RSP; }
Bit64u BX_CPU_C::get_r8(void)  { return R8; }
Bit64u BX_CPU_C::get_r9(void)  { return R9; }
Bit64u BX_CPU_C::get_r10(void) { return R10; }
Bit64u BX_CPU_C::get_r11(void) { return R11; }
Bit64u BX_CPU_C::get_r12(void) { return R12; }
Bit64u BX_CPU_C::get_r13(void) { return R13; }
Bit64u BX_CPU_C::get_r14(void) { return R14; }
Bit64u BX_CPU_C::get_r15(void) { return R15; }
Bit32u BX_CPU_C::get_eflags(void) { return eflags; }

void BX_CPU_C::set_gs_base(uint64_t base) {
  BX_CPU_THIS_PTR sregs[BX_SEG_REG_GS].cache.u.segment.base = (bx_address)base;
}

void BX_CPU_C::clear_cf() {
  clear_CF();
}

Bit32u BX_CPU_C::get_laddr32(unsigned seg, Bit32u offset)
{
  assert(false);
}

#if BX_SUPPORT_X86_64
Bit64u BX_CPU_C::get_laddr64(unsigned seg, Bit64u offset)
{
  if (seg < BX_SEG_REG_FS) {
    return offset;
  } else {
    return BX_CPU_THIS_PTR sregs[seg].cache.u.segment.base + offset;
  }
}
#endif

bx_address BX_CPU_C::get_laddr(unsigned seg, bx_address offset)
{
#if BX_SUPPORT_X86_64
  if (BX_CPU_THIS_PTR cpu_mode == BX_MODE_LONG_64) {
    return get_laddr64(seg, offset);
  }
#endif
  assert(false);
}

// *RMW 系の関数について。
// 以下のようなコメントが書いてあった。
//////////////////////////////////////////////////////////////
// special Read-Modify-Write operations                     //
// address translation info is kept across read/write calls //
//////////////////////////////////////////////////////////////
// とのこと。1命令内でメモリからの read とメモリへの write を同時に行う場合は
// read_linear_qword とかじゃなくてこっちが使われる。
// RMW は Read-Modify-Write の略。
// 対象 read 時に対象の物理メモリを CPU 内に記録するので、
// write 系の命令の引数にはアドレスが無い。
//
// また、virtual と linear があるけど、virtual のほうは
// segment まわりの validation が入る。
// virtual は validation 後に linear を呼び出す。
// このチェックは64bitの場合は行わないようなので、
// 64bit系の命令ではvirtualではなくlinearが使われている。
//
// アドレス変換を行わないので RMW 系の関数は使わずに、
// read_linear_qword とかの関数群を使うこと。

bx_address BX_CPU_C::agen_read(unsigned s, bx_address offset, unsigned len)
{
#if BX_SUPPORT_X86_64
  if (BX_CPU_THIS_PTR cpu_mode == BX_MODE_LONG_64) {
    return get_laddr64(s, offset);
  }
#endif
  return agen_read32(s, offset, len);
}

Bit32u BX_CPU_C::agen_read32(unsigned s, Bit32u offset, unsigned len)
{
  return get_laddr32(s, offset);
}

bx_address BX_CPU_C::agen_read_aligned(unsigned s, bx_address offset, unsigned len)
{
#if BX_SUPPORT_X86_64
  if (BX_CPU_THIS_PTR cpu_mode == BX_MODE_LONG_64) {
    return get_laddr64(s, offset);
  }
#endif
  return agen_read_aligned32(s, offset, len);
}

Bit32u BX_CPU_C::agen_read_aligned32(unsigned s, Bit32u offset, unsigned len)
{
  return get_laddr32(s, offset);
}

bx_address BX_CPU_C::agen_write(unsigned s, bx_address offset, unsigned len)
{
#if BX_SUPPORT_X86_64
  if (BX_CPU_THIS_PTR cpu_mode == BX_MODE_LONG_64) {
    return get_laddr64(s, offset);
  }
#endif
  return agen_write32(s, offset, len);
}

Bit32u BX_CPU_C::agen_write32(unsigned s, Bit32u offset, unsigned len)
{
  return get_laddr32(s, offset);
}

bx_address BX_CPU_C::agen_write_aligned(unsigned s, bx_address offset, unsigned len)
{
#if BX_SUPPORT_X86_64
  if (BX_CPU_THIS_PTR cpu_mode == BX_MODE_LONG_64) {
    return get_laddr64(s, offset);
  }
#endif
  return agen_write_aligned32(s, offset, len);
}

Bit32u BX_CPU_C::agen_write_aligned32(unsigned s, Bit32u offset, unsigned len)
{
  return get_laddr32(s, offset);
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::write_linear_byte(unsigned s, bx_address laddr, Bit8u data)
{
  *((Bit8u*)laddr) = data;
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::write_linear_word(unsigned s, bx_address laddr, Bit16u data)
{
  WriteHostWordToLittleEndian(laddr, data);
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::write_linear_dword(unsigned s, bx_address laddr, Bit32u data)
{
  WriteHostDWordToLittleEndian(laddr, data);
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::write_linear_qword(unsigned s, bx_address laddr, Bit64u data)
{
  WriteHostQWordToLittleEndian(laddr, data);
}

Bit8u BX_CPP_AttrRegparmN(2) BX_CPU_C::read_linear_byte(unsigned s, bx_address laddr)
{
  return *((Bit8u*)laddr);
}

Bit16u BX_CPP_AttrRegparmN(2) BX_CPU_C::read_linear_word(unsigned s, bx_address laddr)
{
  Bit16u data;
  ReadHostWordFromLittleEndian(laddr, data);
  return data;
}

Bit32u BX_CPP_AttrRegparmN(2) BX_CPU_C::read_linear_dword(unsigned s, bx_address laddr)
{
  Bit32u data;
  ReadHostDWordFromLittleEndian(laddr, data);
  return data;
}

Bit64u BX_CPP_AttrRegparmN(2) BX_CPU_C::read_linear_qword(unsigned s, bx_address laddr)
{
  Bit64u data;
  ReadHostQWordFromLittleEndian(laddr, data);
  return data;
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::write_virtual_byte(unsigned s, bx_address offset, Bit8u data)
{
  bx_address laddr = agen_write(s, offset, 1);
  write_linear_byte(s, laddr, data);
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::write_virtual_word(unsigned s, bx_address offset, Bit16u data)
{
  bx_address laddr = agen_write(s, offset, 2);
  write_linear_word(s, laddr, data);
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::write_virtual_dword(unsigned s, bx_address offset, Bit32u data)
{
  bx_address laddr = agen_write(s, offset, 4);
  write_linear_dword(s, laddr, data);
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::write_virtual_qword(unsigned s, bx_address offset, Bit64u data)
{
  bx_address laddr = agen_write(s, offset, 8);
  write_linear_qword(s, laddr, data);
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::write_virtual_byte_32(unsigned s, Bit32u offset, Bit8u data)
{
  Bit32u laddr = agen_write32(s, offset, 1);
  write_linear_byte(s, laddr, data);
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::write_virtual_word_32(unsigned s, Bit32u offset, Bit16u data)
{
  Bit32u laddr = agen_write32(s, offset, 2);
  write_linear_word(s, laddr, data);
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::write_virtual_dword_32(unsigned s, Bit32u offset, Bit32u data)
{
  Bit32u laddr = agen_write32(s, offset, 4);
  write_linear_dword(s, laddr, data);
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::write_virtual_qword_32(unsigned s, Bit32u offset, Bit64u data)
{
  Bit32u laddr = agen_write32(s, offset, 8);
  write_linear_qword(s, laddr, data);
}

Bit8u BX_CPP_AttrRegparmN(2) BX_CPU_C::read_virtual_byte(unsigned s, bx_address offset)
{
  bx_address laddr = agen_read(s, offset, 1);
  return read_linear_byte(s, laddr);
}

Bit16u BX_CPP_AttrRegparmN(2) BX_CPU_C::read_virtual_word(unsigned s, bx_address offset)
{
  bx_address laddr = agen_read(s, offset, 2);
  return read_linear_word(s, laddr);
}

Bit32u BX_CPP_AttrRegparmN(2) BX_CPU_C::read_virtual_dword(unsigned s, bx_address offset)
{
  bx_address laddr = agen_read(s, offset, 4);
  return read_linear_dword(s, laddr);
}

Bit64u BX_CPP_AttrRegparmN(2) BX_CPU_C::read_virtual_qword(unsigned s, bx_address offset)
{
  bx_address laddr = agen_read(s, offset, 8);
  return read_linear_qword(s, laddr);
}

Bit8u BX_CPP_AttrRegparmN(2) BX_CPU_C::read_virtual_byte_32(unsigned s, Bit32u offset)
{
  Bit32u laddr = agen_read32(s, offset, 1);
  return read_linear_byte(s, laddr);
}

Bit16u BX_CPP_AttrRegparmN(2) BX_CPU_C::read_virtual_word_32(unsigned s, Bit32u offset)
{
  Bit32u laddr = agen_read32(s, offset, 2);
  return read_linear_word(s, laddr);
}

Bit32u BX_CPP_AttrRegparmN(2) BX_CPU_C::read_virtual_dword_32(unsigned s, Bit32u offset)
{
  Bit32u laddr = agen_read32(s, offset, 4);
  return read_linear_dword(s, laddr);
}

Bit64u BX_CPP_AttrRegparmN(2) BX_CPU_C::read_virtual_qword_32(unsigned s, Bit32u offset)
{
  Bit32u laddr = agen_read32(s, offset, 8);
  return read_linear_qword(s, laddr);
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::read_linear_xmmword(unsigned s, bx_address laddr, BxPackedXmmRegister *data)
{
  Bit64u *addr = (Bit64u*)laddr;
  ReadHostQWordFromLittleEndian(addr,   data->xmm64u(0));
  ReadHostQWordFromLittleEndian(addr+1, data->xmm64u(1));
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::read_linear_xmmword_aligned(unsigned s, bx_address laddr, BxPackedXmmRegister *data)
{
  if (laddr & 15) {
    assert(false);
  }
  Bit64u *addr = (Bit64u*)laddr;
  ReadHostQWordFromLittleEndian(addr,   data->xmm64u(0));
  ReadHostQWordFromLittleEndian(addr+1, data->xmm64u(1));
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::read_virtual_xmmword(unsigned s, bx_address offset, BxPackedXmmRegister *data)
{
  bx_address laddr = agen_read(s, offset, 16);
  read_linear_xmmword(s, laddr, data);
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::read_virtual_xmmword_32(unsigned s, Bit32u offset, BxPackedXmmRegister *data)
{
  Bit32u laddr = agen_read32(s, offset, 16);
  read_linear_xmmword(s, laddr, data);
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::read_virtual_xmmword_aligned(unsigned s, bx_address offset, BxPackedXmmRegister *data)
{
  bx_address laddr = agen_read_aligned(s, offset, 16);
  read_linear_xmmword_aligned(s, laddr, data);
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::read_virtual_xmmword_aligned_32(unsigned s, Bit32u offset, BxPackedXmmRegister *data)
{
  Bit32u laddr = agen_read_aligned32(s, offset, 16);
  read_linear_xmmword_aligned(s, laddr, data);
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::write_linear_xmmword(unsigned s, bx_address laddr, const BxPackedXmmRegister *data)
{
  Bit64u *addr = (Bit64u*)laddr;
  WriteHostQWordToLittleEndian(addr,   data->xmm64u(0));
  WriteHostQWordToLittleEndian(addr+1, data->xmm64u(1));
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::write_linear_xmmword_aligned(unsigned s, bx_address laddr, const BxPackedXmmRegister *data)
{
  if (laddr & 15) {
    assert(false);
  }
  Bit64u *addr = (Bit64u*)laddr;
  WriteHostQWordToLittleEndian(addr,   data->xmm64u(0));
  WriteHostQWordToLittleEndian(addr+1, data->xmm64u(1));
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::write_virtual_xmmword(unsigned s, bx_address offset, const BxPackedXmmRegister *data)
{
  bx_address laddr = agen_write(s, offset, 16);
  write_linear_xmmword(s, laddr, data);
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::write_virtual_xmmword_32(unsigned s, Bit32u offset, const BxPackedXmmRegister *data)
{
  Bit32u laddr = agen_write32(s, offset, 16);
  write_linear_xmmword(s, laddr, data);
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::write_virtual_xmmword_aligned(unsigned s, bx_address offset, const BxPackedXmmRegister *data)
{
  bx_address laddr = agen_write_aligned(s, offset, 16);
  write_linear_xmmword_aligned(s, laddr, data);
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::write_virtual_xmmword_aligned_32(unsigned s, Bit32u offset, const BxPackedXmmRegister *data)
{
  Bit32u laddr = agen_write_aligned32(s, offset, 16);
  write_linear_xmmword_aligned(s, laddr, data);
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::read_linear_ymmword(unsigned s, bx_address laddr, BxPackedYmmRegister *data)
{
  Bit64u *addr = (Bit64u*)laddr;
  for (unsigned n=0; n < 4; n++) {
    ReadHostQWordFromLittleEndian(addr+n, data->ymm64u(n));
  }
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::read_linear_ymmword_aligned(unsigned s, bx_address laddr, BxPackedYmmRegister *data)
{
  if (laddr & 31) {
    assert(false);
  }

  Bit64u *addr = (Bit64u*)laddr;
  for (unsigned n=0; n < 4; n++) {
    ReadHostQWordFromLittleEndian(addr+n, data->ymm64u(n));
  }
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::read_virtual_ymmword(unsigned s, bx_address offset, BxPackedYmmRegister *data)
{
  bx_address laddr = agen_read(s, offset, 32);
  read_linear_ymmword(s, laddr, data);
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::read_virtual_ymmword_aligned(unsigned s, bx_address offset, BxPackedYmmRegister *data)
{
  bx_address laddr = agen_read_aligned(s, offset, 32);
  read_linear_ymmword_aligned(s, laddr, data);
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::write_linear_ymmword(unsigned s, bx_address laddr, const BxPackedYmmRegister *data)
{
  Bit64u *addr = (Bit64u*)laddr;
  for (unsigned n = 0; n < 4; n++) {
    WriteHostQWordToLittleEndian(addr+n, data->ymm64u(n));
  }
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::write_linear_ymmword_aligned(unsigned s, bx_address laddr, const BxPackedYmmRegister *data)
{
  if (laddr & 31) {
    assert(false);
  }

  Bit64u *addr = (Bit64u*)laddr;
  for (unsigned n = 0; n < 4; n++) {
    WriteHostQWordToLittleEndian(addr+n, data->ymm64u(n));
  }
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::write_virtual_ymmword(unsigned s, bx_address offset, const BxPackedYmmRegister *data)
{
  bx_address laddr = agen_write(s, offset, 32);
  write_linear_ymmword(s, laddr, data);
}

void BX_CPP_AttrRegparmN(3) BX_CPU_C::write_virtual_ymmword_aligned(unsigned s, bx_address offset, const BxPackedYmmRegister *data)
{
  bx_address laddr = agen_write_aligned(s, offset, 32);
  write_linear_ymmword_aligned(s, laddr, data);
}

Bit8u BX_CPP_AttrRegparmN(2) BX_CPU_C::read_RMW_linear_byte(unsigned s, bx_address laddr)
{
  Bit8u data = *((Bit8u*)laddr);
  assert(BX_CPU_THIS_PTR rmw_addr == 0);
  BX_CPU_THIS_PTR rmw_addr = laddr;
  return data;
}

Bit16u BX_CPP_AttrRegparmN(2) BX_CPU_C::read_RMW_linear_word(unsigned s, bx_address laddr)
{
  Bit16u data = *((Bit16u*)laddr);
  assert(BX_CPU_THIS_PTR rmw_addr == 0);
  BX_CPU_THIS_PTR rmw_addr = laddr;
  return data;
}

Bit32u BX_CPP_AttrRegparmN(2) BX_CPU_C::read_RMW_linear_dword(unsigned s, bx_address laddr)
{
  Bit32u data = *((Bit32u*)laddr);
  assert(BX_CPU_THIS_PTR rmw_addr == 0);
  BX_CPU_THIS_PTR rmw_addr = laddr;
  return data;
}

Bit64u BX_CPP_AttrRegparmN(2) BX_CPU_C::read_RMW_linear_qword(unsigned s, bx_address laddr)
{
  Bit64u data = *((Bit64u*)laddr);
  assert(BX_CPU_THIS_PTR rmw_addr == 0);
  BX_CPU_THIS_PTR rmw_addr = laddr;
  return data;
}

void BX_CPU_C::read_RMW_linear_dqword_aligned_64(unsigned s, bx_address laddr, Bit64u *hi, Bit64u *lo)
{
  if (laddr & 15) {
    assert(false);
  }
  ReadHostQWordFromLittleEndian((Bit64u*)(laddr),     *lo);
  ReadHostQWordFromLittleEndian((Bit64u*)(laddr + 1), *hi);
  assert(BX_CPU_THIS_PTR rmw_addr == 0);
  BX_CPU_THIS_PTR rmw_addr = laddr;
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::write_RMW_linear_byte(Bit8u val8)
{
  Bit8u *laddr = (Bit8u*)BX_CPU_THIS_PTR rmw_addr;
  *laddr = val8;
  BX_CPU_THIS_PTR rmw_addr = 0;
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::write_RMW_linear_word(Bit16u val16)
{
  Bit16u *laddr = (Bit16u*) BX_CPU_THIS_PTR rmw_addr;
  WriteHostWordToLittleEndian(laddr, val16);
  BX_CPU_THIS_PTR rmw_addr = 0;
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::write_RMW_linear_dword(Bit32u val32)
{
  Bit32u *laddr = (Bit32u*) BX_CPU_THIS_PTR rmw_addr;
  WriteHostDWordToLittleEndian(laddr, val32);
  BX_CPU_THIS_PTR rmw_addr = 0;
}

void BX_CPP_AttrRegparmN(1) BX_CPU_C::write_RMW_linear_qword(Bit64u val64)
{
  Bit64u *laddr = (Bit64u*) BX_CPU_THIS_PTR rmw_addr;
  WriteHostQWordToLittleEndian(laddr, val64);
  BX_CPU_THIS_PTR rmw_addr = 0;
}

void BX_CPU_C::write_RMW_linear_dqword(Bit64u hi, Bit64u lo)
{
  Bit64u *laddr = (Bit64u*) BX_CPU_THIS_PTR rmw_addr;
  assert(laddr);
  write_RMW_linear_qword(lo);
  // 一つ前の write_RMW_linear_qword でクリアするので再設定しないとダメ。
  BX_CPU_THIS_PTR rmw_addr = (bx_address)(laddr + 1);
  write_RMW_linear_qword(hi);
}

Bit8u BX_CPP_AttrRegparmN(2) BX_CPU_C::read_RMW_virtual_byte(unsigned s, bx_address offset)
{
  bx_address laddr = agen_write(s, offset, 1);
  return read_RMW_linear_byte(s, laddr);
}

Bit16u BX_CPP_AttrRegparmN(2) BX_CPU_C::read_RMW_virtual_word(unsigned s, bx_address offset)
{
  bx_address laddr = agen_write(s, offset, 2);
  return read_RMW_linear_word(s, laddr);
}

Bit32u BX_CPP_AttrRegparmN(2) BX_CPU_C::read_RMW_virtual_dword(unsigned s, bx_address offset)
{
  bx_address laddr = agen_write(s, offset, 4);
  return read_RMW_linear_dword(s, laddr);
}

Bit64u BX_CPP_AttrRegparmN(2) BX_CPU_C::read_RMW_virtual_qword(unsigned s, bx_address offset)
{
  bx_address laddr = agen_write(s, offset, 8);
  return read_RMW_linear_qword(s, laddr);
}

Bit8u BX_CPP_AttrRegparmN(2) BX_CPU_C::read_RMW_virtual_byte_32(unsigned s, Bit32u offset)
{
  Bit32u laddr = agen_write32(s, offset, 1);
  return read_RMW_linear_byte(s, laddr);
}

Bit16u BX_CPP_AttrRegparmN(2) BX_CPU_C::read_RMW_virtual_word_32(unsigned s, Bit32u offset)
{
  Bit32u laddr = agen_write32(s, offset, 2);
  return read_RMW_linear_word(s, laddr);
}

Bit32u BX_CPP_AttrRegparmN(2) BX_CPU_C::read_RMW_virtual_dword_32(unsigned s, Bit32u offset)
{
  Bit32u laddr = agen_write32(s, offset, 4);
  return read_RMW_linear_dword(s, laddr);
}

Bit64u BX_CPP_AttrRegparmN(2) BX_CPU_C::read_RMW_virtual_qword_32(unsigned s, Bit32u offset)
{
  Bit32u laddr = agen_write32(s, offset, 8);
  return read_RMW_linear_qword(s, laddr);
}

void BX_CPP_AttrRegparmN(2) BX_CPU_C::stack_write_byte(bx_address offset, Bit8u data)
{
  *((Bit8u*)offset) = data;
}

void BX_CPP_AttrRegparmN(2) BX_CPU_C::stack_write_word(bx_address offset, Bit16u data)
{
  WriteHostWordToLittleEndian((Bit16u*)offset, data);
}

void BX_CPP_AttrRegparmN(2) BX_CPU_C::stack_write_dword(bx_address offset, Bit32u data)
{
  WriteHostDWordToLittleEndian((Bit32u*)offset, data);
}

void BX_CPP_AttrRegparmN(2) BX_CPU_C::stack_write_qword(bx_address offset, Bit64u data)
{
  WriteHostQWordToLittleEndian((Bit64u*)offset, data);
}

Bit8u BX_CPP_AttrRegparmN(1) BX_CPU_C::stack_read_byte(bx_address offset)
{
  return *((Bit8u*)offset);
}

Bit16u BX_CPP_AttrRegparmN(1) BX_CPU_C::stack_read_word(bx_address offset)
{
  Bit16u data;
  ReadHostWordFromLittleEndian(offset, data);
  return data;
}

Bit32u BX_CPP_AttrRegparmN(1) BX_CPU_C::stack_read_dword(bx_address offset)
{
  Bit32u data;
  ReadHostDWordFromLittleEndian(offset, data);
  return data;
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

void BX_CPP_AttrRegparmN(2) BX_CPU_C::repeat(bxInstruction_c *i, BxRepIterationPtr_tR execute)
{
  // non repeated instruction
  if (! i->repUsedL()) {
    BX_CPU_CALL_REP_ITERATION(execute, (i));
    return;
  }

#if BX_SUPPORT_X86_64
  if (i->as64L()) {
    while(1) {
      if (RCX != 0) {
        BX_CPU_CALL_REP_ITERATION(execute, (i));
        RCX --;
      }
      if (RCX == 0) return;
    }
  }
  else
#endif
  if (i->as32L()) {
    assert(false);
  } else {
    assert(false);
  }
  assert(false);
}

// fpu 関連
void BX_CPU_C::prepareFPU(bxInstruction_c *i, bx_bool check_pending_exceptions)
{
  if (BX_CPU_THIS_PTR cr0.get_EM() || BX_CPU_THIS_PTR cr0.get_TS()) {
    assert(false);
  }

  if (check_pending_exceptions) {
    assert(false);
  }
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

void BX_CPU_C::check_exceptionsSSE(int exceptions_flags)
{
  exceptions_flags &= MXCSR_EXCEPTIONS;
  int unmasked = ~(MXCSR.get_exceptions_masks()) & exceptions_flags;
  // unmasked pre-computational exception detected (#IA, #DE or #DZ)
  if (unmasked & 0x7) exceptions_flags &= 0x7;
  MXCSR.set_exceptions(exceptions_flags);

  if (unmasked)
  {
    assert(false);
  }
}

float_status_t mxcsr_to_softfloat_status_word(bx_mxcsr_t mxcsr)
{
  float_status_t status;

  status.float_exception_flags = 0; // clear exceptions before execution
  status.float_nan_handling_mode = float_first_operand_nan;
  status.float_rounding_mode = mxcsr.get_rounding_mode();
  // if underflow is masked and FUZ is 1, set it to 1, else to 0
  status.flush_underflow_to_zero =
       (mxcsr.get_flush_masked_underflow() && mxcsr.get_UM()) ? 1 : 0;
  status.float_exception_masks = mxcsr.get_exceptions_masks();
  status.float_suppress_exception = 0;
  status.denormals_are_zeros = mxcsr.get_DAZ();

  return status;
}

void BX_CPU_C::write_eflags_fpu_compare(int float_relation)
{
  switch(float_relation) {
   case float_relation_unordered:
      setEFlagsOSZAPC(EFlagsZFMask | EFlagsPFMask | EFlagsCFMask);
      break;

   case float_relation_greater:
      clearEFlagsOSZAPC();
      break;

   case float_relation_less:
      clearEFlagsOSZAPC();
      assert_CF();
      break;

   case float_relation_equal:
      clearEFlagsOSZAPC();
      assert_ZF();
      break;

   default:
      BX_PANIC(("write_eflags: unknown floating point compare relation"));
  }
}

Bit32u BX_CPU_C::get_xinuse_vector(Bit32u requested_feature_bitmap)
{
  Bit32u xinuse = 0;

  if (requested_feature_bitmap & BX_XCR0_FPU_MASK) {
    if (xsave_x87_state_xinuse()) 
      xinuse |= BX_XCR0_FPU_MASK;
  }
  if (requested_feature_bitmap & BX_XCR0_SSE_MASK) {
    if (xsave_sse_state_xinuse() || BX_MXCSR_REGISTER != MXCSR_RESET)
      xinuse |= BX_XCR0_SSE_MASK;
  }
#if BX_SUPPORT_AVX
  if (requested_feature_bitmap & BX_XCR0_YMM_MASK) {
    assert(false);
    //if (xsave_ymm_state_xinuse()) 
      //xinuse |= BX_XCR0_YMM_MASK;
  }
#if BX_SUPPORT_EVEX
  if (requested_feature_bitmap & BX_XCR0_OPMASK_MASK) {
    if (xsave_opmask_state_xinuse()) 
      xinuse |= BX_XCR0_OPMASK_MASK;
  }
  if (requested_feature_bitmap & BX_XCR0_ZMM_HI256_MASK) {
    if (xsave_zmm_hi256_state_xinuse()) 
      xinuse |= BX_XCR0_ZMM_HI256_MASK;
  }
  if (requested_feature_bitmap & BX_XCR0_HI_ZMM_MASK) {
    if (xsave_hi_zmm_state_xinuse()) 
      xinuse |= BX_XCR0_HI_ZMM_MASK;
  }
#endif
#endif

  return xinuse;
}
