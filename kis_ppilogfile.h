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

#ifndef __KIS_PPILOGFILE_H__
#define __KIS_PPILOGFILE_H__

#include "config.h"

#ifdef HAVE_LIBPCAP

#include <stdio.h>
#include <string>

extern "C" {
#if defined(__OpenBSD__)
#include <pcap.h>
#else
#include <pcap/pcap.h>
#endif
}

#include "globalregistry.h"
#include "configfile.h"
#include "messagebus.h"
#include "packetchain.h"
#include "logtracker.h"

// Plugin/module PPI callback
// This is a little wonky; each callback function will be called twice, once with
// allocate set to 1 to indicate how much space it will require in the PPI header,
// and once with the partial header and offset to fill it in.  The return value when
// called with allocate should be the amount of space it will use, while the 
// return value for non-allocate should indicate the new position (absolute new
// position, not offset!)
#define DUMPFILE_PPI_PARMS	int in_allocate, std::shared_ptr<kis_packet> in_pack, uint8_t *dump_data, \
    int dump_pos, void *aux
typedef int (*dumpfile_ppi_cb)(DUMPFILE_PPI_PARMS);

// Filter to return a packet type for logging (used for derivative pcap loggers,
// like in plugins)
#define DUMPFILE_PCAP_FILTER_PARMS	std::shared_ptr<kis_packet> in_pack, void *aux
typedef std::shared_ptr<kis_datachunk> (*dumpfile_pcap_filter_cb)(DUMPFILE_PCAP_FILTER_PARMS);

// Pcap-based packet writer
class kis_ppi_logfile : public kis_logfile {
public:
    kis_ppi_logfile(shared_log_builder in_builder);
    virtual ~kis_ppi_logfile();

	static int packet_handler(CHAINCALL_PARMS);

	virtual void register_ppi_callback(dumpfile_ppi_cb in_cb, void *in_aux);
	virtual void remove_ppi_callback(dumpfile_ppi_cb in_cb, void *in_aux);

    virtual bool open_log(const std::string &in_template, const std::string& in_path) override;
    virtual void close_log() override;

	struct ppi_cb_rec {
		dumpfile_ppi_cb cb;
		void *aux;
	};

protected:
	// Common internal startup
	void startup_dumpfile();

	pcap_t *dumpfile;
	pcap_dumper_t *dumper;
    FILE *dump_filep;

	int dlt;

	std::vector<ppi_cb_rec> ppi_cb_vec;

	dumpfile_pcap_filter_cb cbfilter;
	void *cbaux;

    int pack_comp_80211, pack_comp_mangleframe, pack_comp_radiodata,
        pack_comp_gps, pack_comp_checksum, pack_comp_decap, pack_comp_linkframe,
        pack_comp_common;

    kis_mutex packet_mutex;

    std::atomic<bool> log_open;

    bool log_duplicate_packets;
    bool log_data_packets;
};

class ppi_logfile_builder : public kis_logfile_builder {
public:
    ppi_logfile_builder() :
        kis_logfile_builder() {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    ppi_logfile_builder(int in_id) :
        kis_logfile_builder(in_id) {
           
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    ppi_logfile_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_logfile_builder(in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    virtual ~ppi_logfile_builder() { }

    virtual shared_logfile build_logfile(shared_log_builder builder) override {
        return shared_logfile(new kis_ppi_logfile(builder));
    }

    virtual void initialize() override {
        set_log_class("pcapppi");
        set_log_name("PPI legacy pcap");
        set_stream(true);
        set_singleton(false);
        set_log_description("Legacy-format pcap capture with PPI per-packet "
                "metadata headers");
    }
};

#endif /* pcap */

#endif /* __dump... */
