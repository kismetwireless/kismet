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

#ifndef __KIS_PACKSOURCES_H__
#define __KIS_PACKSOURCES_H__

#include "config.h"

#include "packetsource.h"
#include "prism2source.h"
#include "pcapsource.h"
#include "wtapfilesource.h"
#include "wsp100source.h"
#include "vihasource.h"
#include "dronesource.h"
#include "packetsourcetracker.h"

// Shortcut for registering uncompiled sources
#define REG_EMPTY_CARD(x, y) x->RegisterPacketsource(y, 0, "na", 0, \
                                                     NULL, NULL, NULL, NULL, 0)

// Register all our packet sources.  
//
// We register sources we know about but don't have support compiled in for
// so that the sourcetracker can complain intelligently to the user.
int RegisterKismetSources(Packetsourcetracker *sourcetracker);

#endif
