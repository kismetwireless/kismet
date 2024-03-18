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

struct pcapng_logfile_accept_ftor {
    pcapng_logfile_accept_ftor(bool in_duplicate, bool in_data) :
        log_duplicate_packets{in_duplicate},
        log_data_packets{in_data} {
            auto packetchain = Globalreg::fetch_mandatory_global_as<packet_chain>();
            pack_comp_common = packetchain->register_packet_component("COMMON");
        }

    bool operator()(std::shared_ptr<kis_packet> in_pack) {
        if (in_pack->filtered) {
            return false;
        }

        if (!log_duplicate_packets && in_pack->duplicate) {
            return false;
        }

        if (!log_data_packets) {
            const auto ci = in_pack->fetch<kis_common_info>(pack_comp_common);
            if (ci != nullptr) {
                if (ci->type == packet_basic_data) {
                    return false;
                }
            }
        }

        return true;
    }

    int pack_comp_common;

    bool log_duplicate_packets;
    bool log_data_packets;
};

struct pcapng_logfile_select_ftor {
    pcapng_logfile_select_ftor(bool truncate_duplicate_packets) :
        truncate_duplicate_packets{truncate_duplicate_packets} {
        auto packetchain = Globalreg::fetch_mandatory_global_as<packet_chain>();
        pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");
        pack_comp_l1data = packetchain->register_packet_component("L1RAW");
    }

    std::shared_ptr<kis_datachunk> operator()(std::shared_ptr<kis_packet> in_packet) {
        if (truncate_duplicate_packets && in_packet->duplicate) {
            auto l1data = in_packet->fetch<kis_datachunk>(pack_comp_l1data);
            if (l1data != nullptr) {
                return l1data;
            }
        }

        return in_packet->fetch<kis_datachunk>(pack_comp_linkframe);
    }

    bool truncate_duplicate_packets;
    int pack_comp_linkframe, pack_comp_l1data;
};


class kis_pcapng_logfile : public kis_logfile {
public:
    kis_pcapng_logfile(shared_log_builder in_builder);
    virtual ~kis_pcapng_logfile();

    virtual bool open_log(const std::string& in_temlate, const std::string& in_path) override;
    virtual void close_log() override;

protected:
    void rotate_log();

    pcapng_stream_packetchain<pcapng_logfile_accept_ftor, pcapng_logfile_select_ftor> *pcapng;
    future_chainbuf *buffer;
    FILE *pcapng_file;
    std::thread stream_t;

    bool log_duplicate_packets;
    bool truncate_duplicate_packets;
    bool log_data_packets;

    int pack_comp_common, pack_comp_l1data, pack_comp_linkframe;
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

