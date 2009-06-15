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

#ifndef __POLLABLE_H__
#define __POLLABLE_H__

#include "config.h"

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "globalregistry.h"

// Basic pollable object that anything that gets fed into the select()
// loop in main() should be descended from
class Pollable {
public:
	Pollable() { }
	Pollable(GlobalRegistry *in_globalreg) { globalreg = in_globalreg; }
	virtual ~Pollable() { }

	virtual void RegisterGlobals(GlobalRegistry *in_reg) {
		globalreg = in_reg;
	}

	virtual int MergeSet(int in_max_fd, fd_set *out_rset, fd_set *out_wset) = 0;

	virtual int Poll(fd_set& in_rset, fd_set& in_wset) = 0;

protected:
	GlobalRegistry *globalreg;

};


#endif

