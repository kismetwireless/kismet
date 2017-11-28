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
#include "kis_mutex.h"
#include "trackedelement.h"
#include "kis_net_microhttpd.h"
#include "devicetracker_component.h"
#include "streamtracker.h"

class KisLogfileBuilder;
typedef std::shared_ptr<KisLogfileBuilder> SharedLogBuilder;

class KisLogfile;
typedef std::shared_ptr<KisLogfile> SharedLogfile;

// Logfile builders are responsible for telling the logging tracker what sort of 
// log we are, the type and default name, if we're a singleton log that can't have multiple
// simultaneous instances, how to actually instantiate the log, and various other
// attributes
class KisLogfileBuilder : public tracker_component {
public:
    KisLogfileBuilder(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);

        if (in_id == 0) {
            tracked_id = entrytracker->RegisterField("kismet.log.type_driver",
                    TrackerMap, "Log type definition / driver");
        }

        initialize();
    }

    KisLogfileBuilder(GlobalRegistry *in_globalreg, int in_id, SharedTrackerElement e) :
        tracker_component(in_globalreg, in_id) {

        register_fields();
        reserve_fields(e);

        if (in_id == 0) {
            tracked_id = entrytracker->RegisterField("kismet.log.type_driver",
                    TrackerMap, "Log type definition / driver");
        }

        initialize();
    }

    virtual ~KisLogfileBuilder() { };

    virtual SharedTrackerElement clone_type() {
        return SharedTrackerElement(new KisLogfileBuilder(globalreg, get_id()));
    }

    // Take a shared_ptr reference to ourselves from the caller, because we can't 
    // consistently get a universal shared_ptr to 'this'
    virtual SharedLogfile build_logfile(SharedLogBuilder) {
        return NULL;
    }

    virtual void initialize() { };

    __Proxy(log_class, std::string, std::string, std::string, log_class);
    __Proxy(log_name, std::string, std::string, std::string, log_name);
    __Proxy(stream, uint8_t, bool, bool, stream_log);
    __Proxy(singleton, uint8_t, bool, bool, singleton);
    __Proxy(log_description, std::string, std::string, std::string, description);

protected:
    virtual void register_fields() {
        tracker_component::register_fields();

        RegisterField("kismet.logfile.type.class", TrackerString,
                "class/type", &log_class);
        RegisterField("kismet.logfile.type.name", TrackerString,
                "base type name", &log_name);
        RegisterField("kismet.logfile.type.stream", TrackerUInt8,
                "continual streaming", &stream_log);
        RegisterField("kismet.logfile.type.singleton", TrackerUInt8,
                "single-instance of log type permitted", &singleton);
        RegisterField("kismet.logfile.type.description", TrackerString,
                "base description", &description);
    }

    SharedTrackerElement log_class;
    SharedTrackerElement log_name;
    SharedTrackerElement stream_log;
    SharedTrackerElement singleton;
    SharedTrackerElement description;
};

// Logfiles written to disk can be 'block' logs (like the device log), or they can be
// streaming logs (like gps or pcapng streams); 
class KisLogfile : public tracker_component, public streaming_agent {
public:
    KisLogfile(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    KisLogfile(GlobalRegistry *in_globalreg, int in_id, SharedTrackerElement e) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(e);
    }

    KisLogfile(GlobalRegistry *in_globalreg, SharedLogBuilder in_builder) :
        tracker_component(in_globalreg, 0) {
        register_fields();
        reserve_fields(NULL);
        builder = in_builder;
    }

    virtual ~KisLogfile() { 
        local_eol_locker lock(&log_mutex);

        if (builder != NULL && builder->get_stream()) {
            std::shared_ptr<StreamTracker> streamtracker = 
                Globalreg::FetchGlobalAs<StreamTracker>(globalreg, "STREAMTRACKER");

            streamtracker->remove_streamer(get_stream_id());
        }
    
    }

    virtual SharedTrackerElement clone_type() {
        return SharedTrackerElement(new KisLogfile(globalreg, get_id(), builder));
    }

    virtual bool Log_Open(std::string in_path) { return false; }
    virtual void Log_Close() { }

    __ProxyPrivSplit(log_uuid, uuid, uuid, uuid, log_uuid);
    __ProxyTrackable(builder, KisLogfileBuilder, builder);
    __ProxyPrivSplit(log_path, std::string, std::string, std::string, log_path);
    __ProxyPrivSplit(log_open, uint8_t, bool, bool, log_open);

protected:
    virtual void register_fields() {
        tracker_component::register_fields();

        RegisterField("kismet.logfile.uuid", TrackerUuid,
                "unique log id", &log_uuid);
        RegisterField("kismet.logfile.description", TrackerString,
                "log description", &log_description);
        RegisterField("kismet.logfile.path", TrackerString,
                "filesystem path to log", &log_path);
        RegisterField("kismet.logfile.open", TrackerUInt8,
                "log is currently open", &log_open);

    }

    // Builder/prototype that made us
    SharedLogBuilder builder;

    kis_recursive_timed_mutex log_mutex;

    SharedTrackerElement log_uuid;

    SharedTrackerElement log_description;
    SharedTrackerElement log_path;
    SharedTrackerElement log_open;
};

class LogTracker : public tracker_component, public Kis_Net_Httpd_CPPStream_Handler, 
    public LifetimeGlobal, public DeferredStartup {
public:
    static std::shared_ptr<LogTracker> create_logtracker(GlobalRegistry *in_globalreg) {
        std::shared_ptr<LogTracker> mon(new LogTracker(in_globalreg));
        in_globalreg->RegisterLifetimeGlobal(mon);
        in_globalreg->RegisterDeferredGlobal(mon);
        in_globalreg->InsertGlobal("LOGTRACKER", mon);
        return mon;
    }

    // HTTP API
    virtual bool Httpd_VerifyPath(const char *path, const char *method);

    virtual void Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream);
    virtual int Httpd_PostComplete(Kis_Net_Httpd_Connection *concls);

    virtual void Deferred_Startup();
    virtual void Deferred_Shutdown();

    // Register a log type
    int register_log(SharedLogBuilder in_builder);

    static void Usage(const char *argv0);
private:
    LogTracker(GlobalRegistry *in_globalreg);

public:
    virtual ~LogTracker();

    __ProxyPrivSplit(logging_enabled, uint8_t, bool, bool, logging_enabled);
    __ProxyPrivSplit(log_title, std::string, std::string, std::string, log_title);
    __ProxyPrivSplit(log_prefix, std::string, std::string, std::string, log_prefix);
    __ProxyPrivSplit(log_template, std::string, std::string, std::string, log_template);

protected:
    GlobalRegistry *globalreg;

    virtual void register_fields();
    virtual void reserve_fields(SharedTrackerElement e);

    kis_recursive_timed_mutex tracker_mutex;

    std::shared_ptr<StreamTracker> streamtracker;
    std::shared_ptr<EntryTracker> entrytracker;

    // Vector of prototypes
    SharedTrackerElement logproto_vec;
    int logproto_entry_id;

    // Vector of logs
    SharedTrackerElement logfile_vec;
    int logfile_entry_id;

    // Various global config items common to all
    SharedTrackerElement logging_enabled;
    SharedTrackerElement log_title;
    SharedTrackerElement log_prefix;
    SharedTrackerElement log_template;

    SharedTrackerElement log_types_vec;

};

#endif
    

