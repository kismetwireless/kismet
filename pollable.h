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

// Basic pollable object that plugs into the main pollable system; anything which can
// respond to a poll() or select() should go in this system.  
//
// pollable_merge_set is called to create the FD_SET passed to select(); implementations
// should inspect their buffers and determine if they hold data which should be included
// in the next select loop.  pollable_merge_set must return either the largest FD in the
// set (if larger than in_max_fd), or in the case of unrecoverable error, -1, which will
// remove this pollable from the system forever.  Recoverable errors should return the
// maximum fd number provided.
//
// pollable_poll is called for the results of a select; implementations should check if
// any monitored fds are included in the poll and perform the according read or write
// operations.  Success and recoverable errors should return 0 or a positive number;
// exceptional unrecoverable failures should return -1, which will remove this pollable
// from the polling system forever.
class kis_pollable {
public:
	virtual int pollable_merge_set(int in_max_fd, fd_set *out_rset, fd_set *out_wset) = 0;
	virtual int pollable_poll(fd_set& in_rset, fd_set& in_wset) = 0;
};

#endif

