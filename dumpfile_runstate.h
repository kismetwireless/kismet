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

#ifndef __DUMPFILE_RUNSTATE_H__
#define __DUMPFILE_RUNSTATE_H__

#include "config.h"

#include <stdio.h>
#include <string>

#include "globalregistry.h"
#include "configfile.h"
#include "messagebus.h"
#include "packetchain.h"
#include "alertracker.h"
#include "dumpfile.h"

#define RUNSTATE_VERSION 		1

#define RUNSTATE_PARMS GlobalRegistry *globalreg, void *auxptr, FILE *runfile
typedef void (*RunstateCallback)(RUNSTATE_PARMS);

// Grouped config file writer to dump out runstate stuff
class Dumpfile_Runstate : public Dumpfile {
public:
	Dumpfile_Runstate();
	Dumpfile_Runstate(GlobalRegistry *in_globalreg);
	virtual ~Dumpfile_Runstate();

	virtual int Flush();

	virtual int RegisterRunstateCb(RunstateCallback in_cb, void *in_aux);
	virtual void RemoveRunstateCb(RunstateCallback in_cb);

	typedef struct {
		RunstateCallback cb;
		void *auxdata;
	} runstatecb_rec;

protected:
	FILE *runfile;

	vector<Dumpfile_Runstate::runstatecb_rec *> cb_vec;
};

#endif 

