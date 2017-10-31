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

#include "pollabletracker.h"

PollableTracker::PollableTracker(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;

}

PollableTracker::~PollableTracker() {
    local_eol_locker lock(&pollable_mutex);

}

void PollableTracker::RegisterPollable(shared_ptr<Pollable> in_pollable) {
    local_locker lock(&pollable_mutex);

    add_vec.push_back(in_pollable);
}

void PollableTracker::RemovePollable(shared_ptr<Pollable> in_pollable) {
    local_locker lock(&pollable_mutex);

    remove_vec.push_back(in_pollable);
}

void PollableTracker::Maintenance() {
    local_locker lock(&pollable_mutex);

    for (auto r = remove_vec.begin(); r != remove_vec.end(); ++r) {
        for (auto i = pollable_vec.begin(); i != pollable_vec.end(); ++i) {
            if (*r == *i) {
                pollable_vec.erase(i);
                break;
            }
        }
    }
    remove_vec.clear();

    for (auto i = add_vec.begin(); i != add_vec.end(); ++i) {
        pollable_vec.push_back(*i);
    }
    add_vec.clear();
}

int PollableTracker::MergePollableFds(fd_set *rset, fd_set *wset) {
    local_locker lock(&pollable_mutex);

    Maintenance();

    int max_fd = 0;

    FD_ZERO(rset);
    FD_ZERO(wset);

    for (auto i = pollable_vec.begin(); i != pollable_vec.end(); ++i) {
        max_fd = (*i)->MergeSet(max_fd, rset, wset);
    }

    return max_fd;
}

int PollableTracker::ProcessPollableSelect(fd_set rset, fd_set wset) {
    local_locker lock(&pollable_mutex);
    int r;
    int num = 0;

    Maintenance();

    for (auto i = pollable_vec.begin(); i != pollable_vec.end(); ++i) {
        r = (*i)->Poll(rset, wset);

        if (r >= 0)
            num++;
    }

    return num;
}

