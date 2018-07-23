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

#ifndef __MULTI_CONSTEXPR_H__
#define __MULTI_CONSTEXPR_H__

#include "config.h"

// Very hacky workaround for older distros and compilers that can't support modern
// constexpr features

#ifdef HAVE_CXX14
#define constexpr14 constexpr
#else
#define constexpr14
#endif

#ifdef HAVE_CXX17
#define constexpr17 constexpr
#else
#define constexpr17
#endif

#endif

