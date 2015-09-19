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

static inline uint32_t read_host_dword_from_little_endian(const uint32_t *p) {
  // little endian 固定
  return *p;
}

static inline uint32_t fetch_dword(const uint8_t *ip) {
  return read_host_dword_from_little_endian((const uint32_t*)ip);
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
    assert(false); // FIXME
  }

  return 0;
}
