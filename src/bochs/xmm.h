/////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2015 satoshi shiba
// Copyright (C) 2003-2014 Stanislav Shwartsman
//
// Original source of this file is 'cpu/xmm.h'.
// You can download original source from following link.
// http://sourceforge.net/projects/bochs/files/bochs/2.6.8/
//  -------------------------- Original Copyright ------------------------------
// |////////////////////////////////////////////////////////////////////////////|
// |// $Id: xmm.h 12384 2014-06-25 19:12:14Z sshwarts $                         |
// |////////////////////////////////////////////////////////////////////////////|
// |                                                                            |
// | Copyright (c) 2003-2014 Stanislav Shwartsman                               |
// |        Written by Stanislav Shwartsman [sshwarts at sourceforge net]       |
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

#if BX_SUPPORT_EVEX
#  define BX_VLMAX BX_VL512
#else
#  if BX_SUPPORT_AVX
#    define BX_VLMAX BX_VL256
#  else
#    define BX_VLMAX BX_VL128
#  endif
#endif

#if BX_SUPPORT_EVEX
#  define BX_XMM_REGISTERS 32
#else
#  if BX_SUPPORT_X86_64
#    define BX_XMM_REGISTERS 16
#  else
#    define BX_XMM_REGISTERS 8
#  endif
#endif

#define BX_VECTOR_TMP_REGISTER (BX_XMM_REGISTERS)
