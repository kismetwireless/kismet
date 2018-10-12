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

#ifndef __KISMET_ALGORITHM_H__
#define __KISMET_ALGORITHM_H__

#include "config.h"

#include <memory>

#include <algorithm>

#ifdef HAVE_GNU_PARALLEL
#include <parallel/algorithm>
#endif

#ifdef HAVE_GNU_PARALLEL

#define kismet__sort __gnu_parallel::sort
#define kismet__stable_sort __gnu_parallel::stable_sort
#define kismet__for_each __gnu_parallel::for_each
#define kismet__partial_sort __gnu_parallel::partial_sort

#else 

#define kismet__sort std::sort
#define kismet__stable_sort std::stable_sort
#define kismet__for_each std::for_each
#define kismet__partial_sort std::partial_sort

#endif


#endif

