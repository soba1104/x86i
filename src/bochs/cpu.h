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
#define BX_CPU_H 1

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
