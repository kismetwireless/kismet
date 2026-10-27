/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef __DR_SLJIT_CONFIG_H__
#define __DR_SLJIT_CONFIG_H__

/* Shared by the sljit build and its users; the compiler struct depends on these */

#define SLJIT_CONFIG_AUTO 1

/* Pages are mapped RW, then flipped to RX once generated, so there is never
 * writable code; Apple's allocator does the same with MAP_JIT */
#ifndef __APPLE__
#define SLJIT_WX_EXECUTABLE_ALLOCATOR 1
#endif

#define SLJIT_UTIL_STACK 0
#define SLJIT_VERBOSE 0

#ifdef DR_SLJIT_CHECKS
#define SLJIT_DEBUG 1
#define SLJIT_ARGUMENT_CHECKS 1
#else
#define SLJIT_DEBUG 0
#define SLJIT_ARGUMENT_CHECKS 0
#endif

#endif
