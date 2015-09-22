/////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2015 satoshi shiba
// Copyright (C) 2001-2015  The Bochs Project
//
// Original source of this file is 'cpu/logical8.cc'.
// You can download original source from following link.
// http://sourceforge.net/projects/bochs/files/bochs/2.6.8/
//  -------------------------- Original Copyright ------------------------------
// |////////////////////////////////////////////////////////////////////////////|
// | $Id: logical8.cc 12769 2015-05-16 21:06:59Z sshwarts $
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
// 変更点
// RMW 系命令をそうでないものに置き換えた。

#define NEED_CPU_REG_SHORTCUTS 1
#include "bochs.h"
#include "cpu.h"
#define LOG_THIS BX_CPU_THIS_PTR

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::XOR_EbGbM(bxInstruction_c *i)
{
  Bit8u op1, op2;

  bx_address eaddr = BX_CPU_RESOLVE_ADDR(i);

  op1 = read_virtual_byte(i->seg(), eaddr);
  op2 = BX_READ_8BIT_REGx(i->src(), i->extend8bitL());
  op1 ^= op2;
  write_linear_byte(i->seg(), eaddr, op1);

  SET_FLAGS_OSZAPC_LOGIC_8(op1);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::XOR_GbEbR(bxInstruction_c *i)
{
  Bit8u op1, op2;

  op1 = BX_READ_8BIT_REGx(i->dst(), i->extend8bitL());
  op2 = BX_READ_8BIT_REGx(i->src(), i->extend8bitL());
  op1 ^= op2;
  BX_WRITE_8BIT_REGx(i->dst(), i->extend8bitL(), op1);

  SET_FLAGS_OSZAPC_LOGIC_8(op1);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::XOR_GbEbM(bxInstruction_c *i)
{
  Bit8u op1, op2;

  bx_address eaddr = BX_CPU_RESOLVE_ADDR(i);

  op1 = BX_READ_8BIT_REGx(i->dst(), i->extend8bitL());
  op2 = read_virtual_byte(i->seg(), eaddr);
  op1 ^= op2;
  BX_WRITE_8BIT_REGx(i->dst(), i->extend8bitL(), op1);

  SET_FLAGS_OSZAPC_LOGIC_8(op1);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::XOR_EbIbM(bxInstruction_c *i)
{
  Bit8u op1, op2 = i->Ib();

  bx_address eaddr = BX_CPU_RESOLVE_ADDR(i);

  op1 = read_virtual_byte(i->seg(), eaddr);
  op1 ^= op2;
  write_linear_byte(i->seg(), eaddr, op1);

  SET_FLAGS_OSZAPC_LOGIC_8(op1);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::XOR_EbIbR(bxInstruction_c *i)
{
  Bit8u op1, op2 = i->Ib();

  op1 = BX_READ_8BIT_REGx(i->dst(), i->extend8bitL());
  op1 ^= op2;
  BX_WRITE_8BIT_REGx(i->dst(), i->extend8bitL(), op1);

  SET_FLAGS_OSZAPC_LOGIC_8(op1);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::OR_EbIbM(bxInstruction_c *i)
{
  Bit8u op1, op2 = i->Ib();

  bx_address eaddr = BX_CPU_RESOLVE_ADDR(i);

  op1 = read_virtual_byte(i->seg(), eaddr);
  op1 |= op2;
  write_linear_byte(i->seg(), eaddr, op1);

  SET_FLAGS_OSZAPC_LOGIC_8(op1);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::OR_EbIbR(bxInstruction_c *i)
{
  Bit8u op1, op2 = i->Ib();

  op1 = BX_READ_8BIT_REGx(i->dst(), i->extend8bitL());
  op1 |= op2;
  BX_WRITE_8BIT_REGx(i->dst(), i->extend8bitL(), op1);

  SET_FLAGS_OSZAPC_LOGIC_8(op1);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::NOT_EbM(bxInstruction_c *i)
{
  bx_address eaddr = BX_CPU_RESOLVE_ADDR(i);

  Bit8u op1_8 = read_virtual_byte(i->seg(), eaddr);
  op1_8 = ~op1_8;
  write_linear_byte(i->seg(), eaddr, op1_8);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::NOT_EbR(bxInstruction_c *i)
{
  Bit8u op1_8 = BX_READ_8BIT_REGx(i->dst(), i->extend8bitL());
  op1_8 = ~op1_8;
  BX_WRITE_8BIT_REGx(i->dst(), i->extend8bitL(), op1_8);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::OR_EbGbM(bxInstruction_c *i)
{
  Bit8u op1, op2;

  bx_address eaddr = BX_CPU_RESOLVE_ADDR(i);

  op1 = read_virtual_byte(i->seg(), eaddr);
  op2 = BX_READ_8BIT_REGx(i->src(), i->extend8bitL());
  op1 |= op2;
  write_linear_byte(i->seg(), eaddr, op1);

  SET_FLAGS_OSZAPC_LOGIC_8(op1);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::OR_GbEbR(bxInstruction_c *i)
{
  Bit8u op1, op2;

  op1 = BX_READ_8BIT_REGx(i->dst(), i->extend8bitL());
  op2 = BX_READ_8BIT_REGx(i->src(), i->extend8bitL());
  op1 |= op2;
  BX_WRITE_8BIT_REGx(i->dst(), i->extend8bitL(), op1);

  SET_FLAGS_OSZAPC_LOGIC_8(op1);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::OR_GbEbM(bxInstruction_c *i)
{
  Bit8u op1, op2;

  bx_address eaddr = BX_CPU_RESOLVE_ADDR(i);

  op1 = BX_READ_8BIT_REGx(i->dst(), i->extend8bitL());
  op2 = read_virtual_byte(i->seg(), eaddr);
  op1 |= op2;
  BX_WRITE_8BIT_REGx(i->dst(), i->extend8bitL(), op1);

  SET_FLAGS_OSZAPC_LOGIC_8(op1);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::AND_EbGbM(bxInstruction_c *i)
{
  Bit8u op1, op2;

  bx_address eaddr = BX_CPU_RESOLVE_ADDR(i);

  op1 = read_virtual_byte(i->seg(), eaddr);
  op2 = BX_READ_8BIT_REGx(i->src(), i->extend8bitL());
  op1 &= op2;
  write_linear_byte(i->seg(), eaddr, op1);

  SET_FLAGS_OSZAPC_LOGIC_8(op1);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::AND_GbEbR(bxInstruction_c *i)
{
  Bit8u op1, op2;

  op1 = BX_READ_8BIT_REGx(i->dst(), i->extend8bitL());
  op2 = BX_READ_8BIT_REGx(i->src(), i->extend8bitL());
  op1 &= op2;
  BX_WRITE_8BIT_REGx(i->dst(), i->extend8bitL(), op1);

  SET_FLAGS_OSZAPC_LOGIC_8(op1);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::AND_GbEbM(bxInstruction_c *i)
{
  Bit8u op1, op2;

  bx_address eaddr = BX_CPU_RESOLVE_ADDR(i);

  op1 = BX_READ_8BIT_REGx(i->dst(), i->extend8bitL());
  op2 = read_virtual_byte(i->seg(), eaddr);
  op1 &= op2;
  BX_WRITE_8BIT_REGx(i->dst(), i->extend8bitL(), op1);

  SET_FLAGS_OSZAPC_LOGIC_8(op1);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::AND_EbIbM(bxInstruction_c *i)
{
  Bit8u op1, op2 = i->Ib();

  bx_address eaddr = BX_CPU_RESOLVE_ADDR(i);

  op1 = read_virtual_byte(i->seg(), eaddr);
  op1 &= op2;
  write_linear_byte(i->seg(), eaddr, op1);

  SET_FLAGS_OSZAPC_LOGIC_8(op1);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::AND_EbIbR(bxInstruction_c *i)
{
  Bit8u op1, op2 = i->Ib();

  op1 = BX_READ_8BIT_REGx(i->dst(), i->extend8bitL());
  op1 &= op2;
  BX_WRITE_8BIT_REGx(i->dst(), i->extend8bitL(), op1);

  SET_FLAGS_OSZAPC_LOGIC_8(op1);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::TEST_EbGbR(bxInstruction_c *i)
{
  Bit8u op1, op2;

  op1 = BX_READ_8BIT_REGx(i->dst(), i->extend8bitL());
  op2 = BX_READ_8BIT_REGx(i->src(), i->extend8bitL());
  op1 &= op2;

  SET_FLAGS_OSZAPC_LOGIC_8(op1);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::TEST_EbGbM(bxInstruction_c *i)
{
  Bit8u op1, op2;

  bx_address eaddr = BX_CPU_RESOLVE_ADDR(i);

  op1 = read_virtual_byte(i->seg(), eaddr);
  op2 = BX_READ_8BIT_REGx(i->src(), i->extend8bitL());
  op1 &= op2;

  SET_FLAGS_OSZAPC_LOGIC_8(op1);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::TEST_EbIbR(bxInstruction_c *i)
{
  Bit8u op1 = BX_READ_8BIT_REGx(i->dst(), i->extend8bitL());
  op1 &= i->Ib();
  SET_FLAGS_OSZAPC_LOGIC_8(op1);

  BX_NEXT_INSTR(i);
}

BX_INSF_TYPE BX_CPP_AttrRegparmN(1) BX_CPU_C::TEST_EbIbM(bxInstruction_c *i)
{
  bx_address eaddr = BX_CPU_RESOLVE_ADDR(i);

  Bit8u op1 = read_virtual_byte(i->seg(), eaddr);
  op1 &= i->Ib();
  SET_FLAGS_OSZAPC_LOGIC_8(op1);

  BX_NEXT_INSTR(i);
}
