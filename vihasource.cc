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

#include "config.h"

#include "vihasource.h"

#ifdef HAVE_VIHAHEADERS

int VihaSource::OpenSource(const char *dev, card_type ctype) {
    snprintf(type, 64, "Viha Mac OSX airport card");
    cardtype = ctype;

    // Opening the source doesn't actually need a device, it appears, so just open it.
    wlsource = new WLPacketSource();
    wlsource->open();

}


#endif
