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

#ifdef HAVE_LIBPCAP

#include <errno.h>

#include "dumpfile_pcap.h"

int dumpfilepcap_chain_hook(CHAINCALL_PARMS) {
	Dumpfile_Pcap *auxptr = (Dumpfile_Pcap *) auxdata;
	return auxptr->chain_handler(in_pack);
}

Dumpfile_Pcap::Dumpfile_Pcap() {
	fprintf(stderr, "FATAL OOPS: Dumpfile_Pcap called with no globalreg\n");
	exit(1);
}

Dumpfile_Pcap::Dumpfile_Pcap(GlobalRegistry *in_globalreg) : Dumpfile(in_globalreg) {
	char errstr[STATUS_MAX];
	globalreg = in_globalreg;

	dumpfile = NULL;
	dumper = NULL;

	if (globalreg->sourcetracker == NULL) {
		fprintf(stderr, "FATAL OOPS:  Sourcetracker missing before Dumpfile_Pcap\n");
		exit(1);
	}

	// Find the file name
	if ((fname = ProcessConfigOpt("pcapdump")) == "" || globalreg->fatal_condition) {
		return;
	}

	dumpfile = pcap_open_dead(DLT_IEEE802_11, MAX_PACKET_LEN);
	if (dumpfile == NULL) {
		snprintf(errstr, STATUS_MAX, "Failed to open pcap dump file '%s': %s",
				 fname.c_str(), strerror(errno));
		_MSG(errstr, MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

	dumper = pcap_dump_open(dumpfile, fname.c_str());
	if (dumper == NULL) {
		snprintf(errstr, STATUS_MAX, "Failed to open pcap dump file '%s': %s",
				 fname.c_str(), strerror(errno));
		_MSG(errstr, MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

	globalreg->packetchain->RegisterHandler(&dumpfilepcap_chain_hook, this,
											CHAINPOS_LOGGING, -100);

	_MSG("Opened pcapdump log file '" + fname + "'", MSGFLAG_INFO);
}

Dumpfile_Pcap::~Dumpfile_Pcap() {
	int opened = 0;

	// Close files
	if (dumper != NULL) {
		Flush();
		pcap_dump_flush(dumper);
		pcap_dump_close(dumper);
		opened = 1;
	}

	if (dumpfile != NULL) {
		pcap_close(dumpfile);
	}

	dumper = NULL;
	dumpfile = NULL;

	if (opened) 
		_MSG("Closed pcapdump log file '" + fname + "'", MSGFLAG_INFO);
}

int Dumpfile_Pcap::Flush() {
	if (dumper == NULL || dumpfile == NULL)
		return 0;

	pcap_dump_flush(dumper);

	return 1;
}

int Dumpfile_Pcap::chain_handler(kis_packet *in_pack) {
	kis_datachunk *eight11 = NULL;

	if ((eight11 = 
		 (kis_datachunk *) in_pack->fetch(_PCM(PACK_COMP_80211FRAME))) == NULL) {
		if ((eight11 = 
			(kis_datachunk *) in_pack->fetch(_PCM(PACK_COMP_LINKFRAME))) == NULL) {
			return 0;
		}
	}

	if (eight11->length < 0 || eight11->length > MAX_PACKET_LEN) {
		_MSG("Weird frame in pcap logger with the wrong size...", MSGFLAG_ERROR);
		return 0;
	}

	// Fake a header
	struct pcap_pkthdr wh;
	wh.ts.tv_sec = in_pack->ts.tv_sec;
	wh.ts.tv_usec = in_pack->ts.tv_usec;
	wh.caplen = wh.len = eight11->length;

	// Dump it
	pcap_dump((u_char *) dumper, &wh, eight11->data);

	// fprintf(stderr, "%d %d\n", wh.caplen, dumped_frames);

	dumped_frames++;

	return 1;
}

#endif /* have_libpcap */

