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

#ifndef __KIS_PCAPNGLOGFILE_H__
#define __KIS_PCAPNGLOGFILE_H__

#include "config.h"

#include "globalregistry.h"
#include "logtracker.h"
#include "pcapng_stream_futurebuf.h"

class kis_pcapng_logfile : public kis_logfile {
public:
    kis_pcapng_logfile(shared_log_builder in_builder);
    virtual ~kis_pcapng_logfile();

    virtual bool open_log(std::string in_path) override;
    virtual void close_log() override;

protected:
    pcapng_stream_packetchain *pcapng;
    future_chainbuf buffer;
    FILE *pcapng_file;
    std::thread stream_t;

    bool log_duplicate_packets;
};

class pcapng_logfile_builder : public kis_logfile_builder {
public:
    pcapng_logfile_builder() :
        kis_logfile_builder() {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    pcapng_logfile_builder(int in_id) :
        kis_logfile_builder(in_id) {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    pcapng_logfile_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_logfile_builder(in_id, e) {
        register_fields();
        reserve_fields(e);
        initialize();
    }

    virtual ~pcapng_logfile_builder() { }

    virtual shared_logfile build_logfile(shared_log_builder builder) {
        return shared_logfile(new kis_pcapng_logfile(builder));
    }

    virtual void initialize() {
        set_log_class("pcapng");
        set_log_name("PcapNG pcap");
        set_stream(true);
        set_singleton(false);
        set_log_description("PcapNG multi-interface capture with full original per-packet "
                "metadata headers");
    }

};

#endif

