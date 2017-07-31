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

#ifndef __LOGTRACKER_H__
#define __LOGTRACKER_H__

#include "config.h"

#include <memory>

#include "globalregistry.h"
#include "trackedelement.h"
#include "kis_net_microhttpd.h"
#include "devicetracker_component.h"
#include "streamtracker.h"

// Subset of a streaming agent; an actual log file being written to disk in its
// running instance
class logfile : public streaming_agent {
public:
    logfile(GlobalRegistry *in_globalreg);
    virtual ~logfile();

protected:
    GlobalRegistry *globalreg;

};

class LogTracker : public Kis_Net_Httpd_CPPStream_Handler, public LifetimeGlobal {
public:
    static shared_ptr<LogTracker> create_logtracker(GlobalRegistry *in_globalreg) {
        shared_ptr<LogTracker> mon(new LogTracker(in_globalreg));
        in_globalreg->RegisterLifetimeGlobal(mon);
        in_globalreg->InsertGlobal("LOGTRACKER", mon);
        return mon;
    }

    // HTTP API
    virtual bool Httpd_VerifyPath(const char *path, const char *method);

    virtual void Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream);

private:
    LogTracker(GlobalRegistry *in_globalreg);

public:
    virtual ~LogTracker();

protected:
    GlobalRegistry *globalreg;

    shared_ptr<StreamTracker> streamtracker;

};

#endif
    

