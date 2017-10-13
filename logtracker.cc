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

#include "logtracker.h"
#include "globalregistry.h"

LogTracker::LogTracker(GlobalRegistry *in_globalreg) :
    Kis_Net_Httpd_CPPStream_Handler(in_globalreg) {

    globalreg = in_globalreg;

    streamtracker =
        Globalreg::FetchMandatoryGlobalAs<StreamTracker>(globalreg, "STREAMTRACKER");

    logproto_vec =
        entrytracker->RegisterAndGetField("kismet.logtracker.driver",
                SharedLogBuilder(new KisLogfileBuilder(globalreg, 0)),
                "Log driver");

    log_vec =
        entrytracker->RegisterAndGetField("kismet.logtracker.log",
                SharedLogfile(new KisLogfile(globalreg, 0)),
                "Log file");

}

