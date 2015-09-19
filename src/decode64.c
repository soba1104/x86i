// bochs/cpu/fetchdecode64.cc の改変

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <assert.h>

#define BX_SUPPORT_X86_64 1 // FIXME
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

#define X 0 /* undefined opcode */

static const uint8_t opcode_has_modrm_64[512] = {
  /*       0 1 2 3 4 5 6 7 8 9 a b c d e f          */
  /*       -------------------------------          */
  /* 00 */ 1,1,1,1,0,0,X,X,1,1,1,1,0,0,X,X,
  /* 10 */ 1,1,1,1,0,0,X,X,1,1,1,1,0,0,X,X,
  /* 20 */ 1,1,1,1,0,0,X,X,1,1,1,1,0,0,X,X,
  /* 30 */ 1,1,1,1,0,0,X,X,1,1,1,1,0,0,X,X,
  /* 40 */ X,X,X,X,X,X,X,X,X,X,X,X,X,X,X,X,
  /* 50 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  /* 60 */ X,X,X,1,X,X,X,X,0,1,0,1,0,0,0,0,
  /* 70 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  /* 80 */ 1,1,X,1,1,1,1,1,1,1,1,1,1,1,1,1,
  /* 90 */ 0,0,0,0,0,0,0,0,0,0,X,0,0,0,0,0,
  /* A0 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  /* B0 */ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  /* C0 */ 1,1,0,0,X,X,1,1,0,0,0,0,0,0,X,0,
  /* D0 */ 1,1,1,1,X,X,X,0,1,1,1,1,1,1,1,1,
  /* E0 */ 0,0,0,0,0,0,0,0,0,0,X,0,0,0,0,0,
  /* F0 */ X,0,X,X,0,0,1,1,0,0,0,0,0,0,1,1,
  /*       0 1 2 3 4 5 6 7 8 9 a b c d e f           */
  /*       -------------------------------           */
           1,1,1,1,X,0,0,0,0,0,X,0,X,1,0,1, /* 0F 00 */
           1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 0F 10 */
           1,1,1,1,X,X,X,X,1,1,1,1,1,1,1,1, /* 0F 20 */
           0,0,0,0,X,X,X,X,1,X,1,X,X,X,X,X, /* 0F 30 */
           1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 0F 40 */
           1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 0F 50 */
           1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 0F 60 */
           1,1,1,1,1,1,1,0,1,1,X,X,1,1,1,1, /* 0F 70 */
           0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 0F 80 */
           1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 0F 90 */
           0,0,0,1,1,1,X,X,0,0,0,1,1,1,1,1, /* 0F A0 */
           1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 0F B0 */
           1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0, /* 0F C0 */
           1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 0F D0 */
           1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 0F E0 */
           1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,X  /* 0F F0 */
  /*       -------------------------------           */
  /*       0 1 2 3 4 5 6 7 8 9 a b c d e f           */
};

#undef X

static inline uint16_t read_host_word_from_little_endian(const uint16_t *p) {
  // little endian 固定
  return *p;
}

static inline uint32_t read_host_dword_from_little_endian(const uint32_t *p) {
  // little endian 固定
  return *p;
}

static inline uint64_t read_host_qword_from_little_endian(const uint64_t *p) {
  // little endian 固定
  return *p;
}

static inline uint16_t fetch_word(const uint8_t *ip) {
  return read_host_word_from_little_endian((const uint16_t*)ip);
}

static inline uint32_t fetch_dword(const uint8_t *ip) {
  return read_host_dword_from_little_endian((const uint32_t*)ip);
}

static inline uint64_t fetch_qword(const uint8_t *ip) {
  return read_host_qword_from_little_endian((const uint64_t*)ip);
}

typedef struct {
} opcode_info_t;

typedef struct {
} insn_t;

// bxInstruction_c::init 相当
static inline void insn_init(insn_t *insn) {
}

// bxInstruction_c::setOs32B 相当
static inline void insn_set_operand_size_32_bit(insn_t *insn, uint8_t bit) {
}

// bxInstruction_c::clearAs64 相当
static inline void insn_clear_address_size_64(insn_t *insn) {
}

// bxInstruction_c::assertExtend8bit 相当
static inline void insn_set_extend_8bit(insn_t *insn) {
}

// bxInstruction_c::assertOs64 相当
static inline void insn_set_operand_size_64(insn_t *insn) {
}

// bxInstruction_c::assertOs32 相当
static inline void insn_set_operand_size_32(insn_t *insn) {
}

// bxInstruction_c::os32L相当
static inline uint32_t insn_get_operand_size_32UL(insn_t *insn) {
  return 0; // FIXME
}

// bxInstruction_c::assertModC0 相当
static inline void insn_set_mod_c0(insn_t *insn) {
}

// bxInstruction_c::setSibBase 相当
static inline void insn_set_sib_base(insn_t *insn, uint32_t base) {
}

// bxInstruction_c::setSibIndex 相当
static inline void insn_set_sib_index(insn_t *insn, uint32_t index) {
}

// bxInstruction_c.modRMForm.Id の設定
static inline void insn_set_modrm_form_id(insn_t *insn, uint32_t id) {
}

// bx_Instruction_c.modRMForm.displ32u の設定
static inline void insn_set_modrm_form_displ32u(insn_t *insn, uint32_t displ32u) {
}

// bx_Instruction_c.modRMForm.Ib の設定
static inline void insn_set_modrm_form_ib(insn_t *insn, uint8_t index, uint8_t byte) {
}

// bx_Instruction_c.modRMForm.Iw の設定
static inline void insn_set_modrm_form_iw(insn_t *insn, uint8_t index, uint16_t word) {
}

// bx_Instruction_c.IqForm.Iq の設定
static inline void insn_set_iq_form_iq(insn_t *insn, uint64_t qword) {
}

#define BX_IA_ERROR 0 // FIXME
int decode(uint8_t **ipp, insn_t *insn) {
  unsigned b1, b2 = 0, ia_opcode = BX_IA_ERROR, imm_mode = 0;
  unsigned offset = 512, rex_r = 0, rex_x = 0, rex_b = 0;
  unsigned rm = 0, mod = 0, nnn = 0, mod_mem = 0;
  bool lock = 0;
  uint8_t *ip = *ipp;

#define SSE_PREFIX_NONE 0
#define SSE_PREFIX_66   1
#define SSE_PREFIX_F3   2
#define SSE_PREFIX_F2   3
  unsigned sse_prefix = SSE_PREFIX_NONE;
  unsigned rex_prefix = 0;

  bool vex_w = 0;

  insn_init(insn);

fetch_b1:
  b1 = *ip++;

  switch(b1) {
    // rex prefix
    case 0x40 ... 0x4f:
      rex_prefix = b1;
      goto fetch_b1;

    // 2 byte escape
    case 0x0f:
      b1 = 0x100 | *ip++;
      break;

    // REPNE/REPNZ
    case 0xf2:
      assert(false);

    // REP/REPE/REPZ
    case 0xf3:
      assert(false);

    // segment override prefixes
    case 0x2e: // CS:
    case 0x26: // ES:
    case 0x36: // SS:
    case 0x3e: // DS:
    case 0x64: // FS:
    case 0x65: // GS:
      assert(false);

    // opcode size prefix
    case 0x66: // OpSize
      rex_prefix = 0;
      if (!sse_prefix) sse_prefix = SSE_PREFIX_66;
      insn_set_operand_size_32_bit(insn, 0);
      offset = 0;
      goto fetch_b1;

    // address size prefix
    case 0x67: // AddrSize
      rex_prefix = 0;
      insn_clear_address_size_64(insn);
      goto fetch_b1;

    // lock prefix
    case 0xf0:
      rex_prefix = 0;
      lock = 1;
      goto fetch_b1;
    default:
      break;
  }

  if (rex_prefix) {
    insn_set_extend_8bit(insn);
    if (rex_prefix & 0x8) {
      insn_set_operand_size_64(insn);
      insn_set_operand_size_32(insn);
      offset = 512*2;
    }
    rex_r = ((rex_prefix & 0x4) << 1);
    rex_x = ((rex_prefix & 0x2) << 2);
    rex_b = ((rex_prefix & 0x1) << 3);
  }

  insn_set_modrm_form_id(insn, 0);

  unsigned index = b1 + offset;
  /*const BxOpcodeInfo_t *OpcodeInfoPtr = &(BxOpcodeInfo64[index]);*/
  /*Bit16u attr = OpcodeInfoPtr->Attr;*/
  const opcode_info_t *opcode_info = NULL; // FIXME
  uint16_t attr = 0; // FIXME

  bool has_modrm = 0;

  if ((b1 & ~0x1) == 0xc4) {
    assert(false);
  } else if (b1 == 0x62) {
    assert(false);
  } else if (b1 == 0x8f && (*ip & 0x08) == 0x08) {
    assert(false);
  } else {
    has_modrm = opcode_has_modrm_64[b1];
  }

  if (has_modrm) {
    // handle 3-byte escape
    if (b1 == 0x138 || b1 == 0x13a) {
      assert(false);
    }

    // opcode requires modrm byte
    b2 = *ip++;

    // Parse mod-nnn-rm and related bytes
    mod = b2 & 0xc0;
    nnn = ((b2 >> 3) & 0x7) | rex_r;
    rm  = (b2 & 0x7) | rex_b;

    // for x87
    if (b1 >= 0xd8 && b1 <= 0xdf) {
      assert(false);
    }

    // MOVs with CRx and DRx always use register ops and ignore the mod field.
    if ((b1 & ~3) == 0x120) {
      mod = 0xc0;
    }

    // mod == 11b, メモリではなくレジスタを使うモード
    if (mod == 0xc0) {
      insn_set_mod_c0(insn);
      goto modrm_done;
    }

    mod_mem = 1;
    insn_set_sib_base(insn, rm & 0xf); // initialize with rm to use BxResolve64Base
    insn_set_sib_index(insn, 4);
    // initialize displ32 with zero to include cases with no diplacement
    insn_set_modrm_form_displ32u(insn, 0);

    // note that mod==11b handled above

    if ((rm & 0x7) != 4) { // no s-i-b byte
      if (mod == 0x00) { // mod == 00b
        if ((rm & 0x7) == 5) {
          insn_set_sib_base(insn, BX_64BIT_REG_RIP);
          goto get_32bit_displ;
        }
        // mod==00b, rm!=4, rm!=5
        goto modrm_done;
      }
      // (mod == 0x40), mod==01b or (mod == 0x80), mod==10b
      assert(false);
    } else { // mod!=11b, rm==4, s-i-b byte follows
      assert(false);
    }

    // (mod == 0x40), mod==01b
    if (mod == 0x40) {
      // 8 sign extended to 32
      insn_set_modrm_form_displ32u(insn, (int8_t)*ip++);
    } else {
get_32bit_displ:
      // (mod == 0x80), mod==10b
      insn_set_modrm_form_displ32u(insn, fetch_dword(ip));
      ip += 4;
    }

modrm_done:
    // FIXME
    /*ia_opcode = WalkOpcodeTables(OpcodeInfoPtr, attr, b2, sse_prefix, offset >> 9, i->getVL(), vex_w);*/
    ia_opcode = 0;
  } else {
    // Opcode does not require a MODRM byte.
    // Note that a 2-byte opcode (0F XX) will jump to before
    // the if() above after fetching the 2nd byte, so this path is
    // taken in all cases if a modrm byte is NOT required.

    unsigned group = attr & BxGroupX;
    if (group == BxPrefixSSE && sse_prefix) {
      assert(false);
    }

    /*ia_opcode = OpcodeInfoPtr->IA; // FIXME*/
    ia_opcode = 0;
    rm = (b1 & 7) | rex_b;
    nnn = (b1 >> 3) & 7;
    insn_set_mod_c0(insn);
    if (b1 == 0x90) {
      assert(false);
    }
  }

  if (lock) {
    assert(false);
  }

  imm_mode = attr & BxImmediate;
  int8_t temp8s = 0;
  if (imm_mode) {
    // make sure iptr was advanced after Ib(), Iw() and Id()
    switch (imm_mode) {
      case BxImmediate_I1:
        insn_set_modrm_form_ib(insn, 0, 1);
        break;
      case BxImmediate_Ib:
        insn_set_modrm_form_ib(insn, 0, *ip++);
        break;
      case BxImmediate_Ib_SE: // Sign extend to OS size
        // TODO ip の更新が不要なのかどうか確認
        temp8s = *ip;
        // this code works correctly both for LE and BE hosts
        if (insn_get_operand_size_32UL(insn)) {
          insn_set_modrm_form_id(insn, (int32_t)temp8s);
        } else {
          insn_set_modrm_form_iw(insn, 0, (int16_t)temp8s);
        }
        break;
      case BxImmediate_BrOff8:
        // TODO ip の更新が不要なのかどうか確認
        temp8s = *ip;
        insn_set_modrm_form_id(insn, (int32_t)temp8s);
        break;
      case BxImmediate_Iw:
        insn_set_modrm_form_iw(insn, 0, fetch_word(ip));
        ip += 2;
        break;
      case BxImmediate_Id:
        insn_set_modrm_form_id(insn, fetch_dword(ip));
        ip += 4;
        break;
      case BxImmediate_Iq: // MOV Rx,imm64
        // TODO ip の更新が不要なのかどうか確認
        insn_set_iq_form_iq(insn, fetch_qword(ip));
        break;
      case BxImmediate_O:
        assert(false);
      default:
        assert(false);
    }

    {
      unsigned imm_mode2 = attr & BxImmediate2;
      if (imm_mode2) {
        if (imm_mode2 == BxImmediate_Ib2) {
          // TODO ip の更新が不要なのかどうか確認
          insn_set_modrm_form_ib(insn, 0, *ip);
        } else {
          assert(false);
        }
      }
    }
  }

  return 0;
}
