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

#ifndef __DUMPFILE_Devicetracker_H__
#define __DUMPFILE_Devicetracker_H__

#include "config.h"

#include <stdio.h>
#include <string>

#include "globalregistry.h"
#include "configfile.h"
#include "messagebus.h"
#include "dumpfile.h"

// Tightly integrated with devicetracker; this wraps the file IO in a standard
// dumpfile, then hands off population of the file to the devicetracker

class Dumpfile_Devicetracker : public Dumpfile {
public:
	Dumpfile_Devicetracker();
	Dumpfile_Devicetracker(GlobalRegistry *in_globalreg);
	Dumpfile_Devicetracker(GlobalRegistry *in_globalreg, string in_type, 
						   string in_class);
	virtual ~Dumpfile_Devicetracker();

	virtual int Flush();
protected:
	FILE *logfile;
};

#endif /* __dump... */
	
