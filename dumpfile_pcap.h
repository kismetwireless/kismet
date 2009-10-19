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

#ifndef __DUMPFILE_PCAP_H__
#define __DUMPFILE_PCAP_H__

#include "config.h"

#ifdef HAVE_LIBPCAP
#include <stdio.h>
#include <string>

extern "C" {
#ifndef HAVE_PCAPPCAP_H
#include <pcap.h>
#else
#include <pcap/pcap.h>
#endif
}

#include "globalregistry.h"
#include "configfile.h"
#include "messagebus.h"
#include "packetchain.h"
#include "dumpfile.h"

// Hook for grabbing packets
int dumpfilepcap_chain_hook(CHAINCALL_PARMS);

enum dumpfile_pcap_format {
	dump_unknown, dump_dlt, dump_ppi
};

// Plugin/module PPI callback
// This is a little wonky; each callback function will be called twice, once with
// allocate set to 1 to indicate how much space it will require in the PPI header,
// and once with the partial header and offset to fill it in.  The return value when
// called with allocate should be the amount of space it will use, while the 
// return value for non-allocate should indicate the new position (absolute new
// position, not offset!)
#define DUMPFILE_PPI_PARMS	GlobalRegistry *in_globalreg, int in_allocate, \
	kis_packet *in_pack, uint8_t *dump_data, int dump_pos, void *aux
typedef int (*dumpfile_ppi_cb)(DUMPFILE_PPI_PARMS);

// Filter to return a packet type for logging (used for derivative pcap loggers,
// like in plugins)
#define DUMPFILE_PCAP_FILTER_PARMS	GlobalRegistry *in_globalreg, kis_packet *in_pack, \
	void *aux
typedef kis_datachunk *(*dumpfile_pcap_filter_cb)(DUMPFILE_PCAP_FILTER_PARMS);

// Pcap-based packet writer
class Dumpfile_Pcap : public Dumpfile {
public:
	Dumpfile_Pcap();
	Dumpfile_Pcap(GlobalRegistry *in_globalreg);

	// Alternate constructor for custom pcap logs (ie plugins)
	// New type overrides 'pcapdump'.
	// Passing a pointer to a "parent" pcapfile will attach and share
	// callbacks for the PPI system, in a fugly nasty way.
	Dumpfile_Pcap(GlobalRegistry *in_globalreg, string in_type, 
				  int in_dlt, Dumpfile_Pcap *in_parent,
				  dumpfile_pcap_filter_cb in_filter, void *in_aux);

	virtual ~Dumpfile_Pcap();

	virtual int chain_handler(kis_packet *in_pack);
	virtual int Flush();

	virtual void RegisterPPICallback(dumpfile_ppi_cb in_cb, void *in_aux);
	virtual void RemovePPICallback(dumpfile_ppi_cb in_cb, void *in_aux);

	struct ppi_cb_rec {
		dumpfile_ppi_cb cb;
		void *aux;
	};

protected:
	Dumpfile_Pcap *parent;

	// Common internal startup
	void Startup_Dumpfile();

	pcap_t *dumpfile;
	pcap_dumper_t *dumper;

	int beaconlog, phylog, corruptlog;
	dumpfile_pcap_format dumpformat;

	int dlt;

	macmap<uint32_t> bssid_csum_map;

	vector<ppi_cb_rec> ppi_cb_vec;

	dumpfile_pcap_filter_cb cbfilter;
	void *cbaux;
};

#endif /* pcap */

#endif /* __dump... */
	
