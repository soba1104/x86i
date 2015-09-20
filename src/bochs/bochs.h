/////////////////////////////////////////////////////////////////////////////////
// Copyright (C) 2015 satoshi shiba
// Copyright (C) 2001-2015  The Bochs Project
//
// Original source of this file is 'bochs.h'.
// You can download original source from following link.
// http://sourceforge.net/projects/bochs/files/bochs/2.6.8/
//  -------------------------- Original Copyright ------------------------------
// |////////////////////////////////////////////////////////////////////////////|
// |// $Id: bochs.h 12749 2015-05-05 18:06:05Z vruppert $                       |
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

#ifndef BX_BOCHS_H
#define BX_BOCHS_H 1

BX_CPP_INLINE Bit16u bx_bswap16(Bit16u val16)
{
  return (val16<<8) | (val16>>8);
}

BX_CPP_INLINE Bit32u bx_bswap32(Bit32u val32)
{
  val32 = ((val32<<8) & 0xFF00FF00) | ((val32>>8) & 0x00FF00FF);
  return (val32<<16) | (val32>>16);
}

BX_CPP_INLINE Bit64u bx_bswap64(Bit64u val64)
{
  Bit32u lo = bx_bswap32((Bit32u)(val64 >> 32));
  Bit32u hi = bx_bswap32((Bit32u)(val64 & 0xFFFFFFFF));
  return ((Bit64u)hi << 32) | (Bit64u)lo;
}

#ifdef BX_LITTLE_ENDIAN

#define WriteHostWordToLittleEndian(hostPtr,  nativeVar16) \
    *((Bit16u*)(hostPtr)) = (nativeVar16)
#define WriteHostDWordToLittleEndian(hostPtr, nativeVar32) \
    *((Bit32u*)(hostPtr)) = (nativeVar32)
#define WriteHostQWordToLittleEndian(hostPtr, nativeVar64) \
    *((Bit64u*)(hostPtr)) = (nativeVar64)

#define ReadHostWordFromLittleEndian(hostPtr,  nativeVar16) \
    (nativeVar16) = *((Bit16u*)(hostPtr))
#define ReadHostDWordFromLittleEndian(hostPtr, nativeVar32) \
    (nativeVar32) = *((Bit32u*)(hostPtr))
#define ReadHostQWordFromLittleEndian(hostPtr, nativeVar64) \
    (nativeVar64) = *((Bit64u*)(hostPtr))

#else

#define WriteHostWordToLittleEndian(hostPtr,  nativeVar16) {  \
    *(Bit16u *)(hostPtr) = bx_bswap16((Bit16u)(nativeVar16)); \
}
#define WriteHostDWordToLittleEndian(hostPtr, nativeVar32) {  \
    *(Bit32u *)(hostPtr) = bx_bswap32((Bit32u)(nativeVar32)); \
}
#define WriteHostQWordToLittleEndian(hostPtr, nativeVar64) {  \
    *(Bit64u *)(hostPtr) = bx_bswap64((Bit64u)(nativeVar64)); \
}

#define ReadHostWordFromLittleEndian(hostPtr, nativeVar16) {  \
    (nativeVar16) =  bx_bswap16(*(Bit16u *)(hostPtr));        \
}
#define ReadHostDWordFromLittleEndian(hostPtr, nativeVar32) { \
    (nativeVar32) =  bx_bswap32(*(Bit32u *)(hostPtr));        \
}
#define ReadHostQWordFromLittleEndian(hostPtr, nativeVar64) { \
    (nativeVar64) =  bx_bswap64(*(Bit64u *)(hostPtr));        \
}

#endif

#endif // BX_BOCHS_H
