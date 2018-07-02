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

#ifndef __STORAGELOADER_H__
#define __STORAGELOADER_H__

#include <string>
#include <memory>
#include <fstream>
#include <iostream>

#include "trackedelement.h"
#include "entrytracker.h"
#include "structured.h"

/* Storage loaders convert common StructuredData elements to tracked element object trees,
 * which can then be adopted by complete classes.
 *
 */

namespace StorageLoader {

SharedTrackerElement storage_to_tracker(SharedStructured d); 

};

#endif

