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

#ifndef __SDR_IQ_TRACKER_H__
#define __SDR_IQ_TRACKER_H__

#include "config.h"

#include <atomic>
#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>

#include "globalregistry.h"

class SdrIQtracker : public LifetimeGlobal {
public:
    static std::string global_name() { return "SDRIQTRACKER"; }

    static std::shared_ptr<SdrIQtracker> create_devicetracker() {
        std::shared_ptr<SdrIQtracker> mon(new SdrIQtracker());
        Globalreg::globalreg->RegisterLifetimeGlobal(mon);
        Globalreg::globalreg->InsertGlobal(global_name(), mon);
        return mon;
    }

private:
	SdrIQtracker();

public:
	virtual ~SdrIQtracker();

};

#endif

