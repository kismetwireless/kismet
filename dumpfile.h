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

#ifndef __DUMPFILE_H__
#define __DUMPFILE_H__

#include "config.h"

#include <stdio.h>
#include <string>

#include "globalregistry.h"
#include "configfile.h"
#include "messagebus.h"
#include "packetchain.h"

class Dumpfile {
public:
	Dumpfile();
	Dumpfile(GlobalRegistry *in_globalreg);
	virtual ~Dumpfile() { };

	virtual int chain_handler(kis_packet *in_pack) = 0;

	int FetchNumDumped() { return dumped_frames; }

protected:
	GlobalRegistry *globalreg;
	string fname;
	FILE *dumpfile;

	int dumped_frames;

	virtual int ProcessConfigOpt(string in_type);
};

#endif

