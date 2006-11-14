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

#if defined(HAVE_LIBPCAP) && defined(HAVE_LIBAIRPCAP) && defined(SYS_CYGWIN)

#include "airpcapsource.h"

// Prototypes of Windows-specific pcap functions.
// wpcap.dll contains these functions, but they are not exported to cygwin because
// cygwin doesn't "officially" support the Windows extensions. These functions, 
// however, are safe to use.
extern "C" PAirpcapHandle pcap_get_airpcap_handle(pcap_t *p);
extern "C" HANDLE pcap_getevent (pcap_t *p);
extern "C" int pcap_setmintocopy (pcap_t *p, int size);

int AirPcapSource::OpenSource() {
	channel = 0;
	errstr[0] = '\0';

	char *unconst = strdup(interface.c_str());
	
	pd = pcap_open_live(unconst, MAX_PACKET_LEN, 1, 1000, errstr);

	free(unconst);

	if (strlen(errstr) > 0)
		return -1;

	paused = 0;
	errstr[0] = '\0';

	// Gather the data link
    if (DatalinkType() < 0) {
		snprintf(errstr, 1024, "unable to get the data link on %s",
				 interface.c_str());
		pcap_close(pd);
		return -1;
	}
	
	// Fetch the airpcap channel
	if ((airpcap_handle = pcap_get_airpcap_handle(pd)) == NULL) {
		snprintf(errstr, 1024, "Adapter %s does not have wireless extensions",
				 interface.c_str());
		pcap_close(pd);
		return -1;
	}

	// Set the link mode to give us radiotap headers
	if (!AirpcapSetLinkType(airpcap_handle, AIRPCAP_LT_802_11_PLUS_RADIO)) {
		snprintf(errstr, 1024, "Adapter %s failed setting radiotap link layer: %s",
				 interface.c_str(), AirpcapGetLastError(airpcap_handle));
		pcap_close(pd);
		return -1;
	}

	// Tell the AirPcap adapter that we want the correct frames only
	// (XXX Is this needed?) 
	// (XXX It doesn't hurt.  Kismet doesn't do anything but validate FCS itself
	// and throw them out, so we might as well toss them out at the
	// airpcap level - dragorn)
	if (!AirpcapSetFcsValidation(airpcap_handle, AIRPCAP_VT_ACCEPT_CORRECT_FRAMES)) {
		snprintf(errstr, 1024, "Adapter %s failed setting radiotap link layer: %s",
				 interface.c_str(), AirpcapGetLastError(airpcap_handle));
		pcap_close(pd);
		return -1;
	}

	// Add it to our local copy of the fd event mangler
	fd_mangle.AddHandle(pcap_getevent(pd));
	fd_mangle.Activate();

	return 0;
}

int AirPcapSource::FetchChannel() {
	unsigned int ch;
	if (!AirpcapGetDeviceChannel(airpcap_handle, &ch))
		return -1;

	return (int) ch;
}

int AirPcapSource::FetchDescriptor() {
	// Fall through to our HANDLE to FD mangler
	return fd_mangle.GetFd();
}

int AirPcapSource::SetChannel(unsigned int in_ch, char *in_err) {
	if (!AirpcapSetDeviceChannel(airpcap_handle, in_ch)) {
		snprintf(in_err, 1024, "Adapter %s failed setting channel: %s",
				 interface.c_str(), AirpcapGetLastError(airpcap_handle));
		return -1;
	}

	return 0;
}

int AirPcapSource::FetchSignalLevels(int *in_siglev, int *in_noiselev) {
	*in_siglev = 0;
	*in_noiselev = 0;

	return 0;
}

KisPacketSource *airpcapsource_registrant(string in_name, string in_device,
										  char *in_err) {
	return new AirPcapSource(in_name, in_device);
}

// Spawn an airpcap device and get the info from the user
KisPacketSource *airpcapsourceq_registrant(string in_name, string in_device,
										   char *in_err) {
	pcap_if_t *alldevs, *d;
	int i;
	int intnum;
	AirPcapSource *src = NULL;
	char errbuf[1024];

	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		snprintf(in_err, 1024, "Error in pcap_findalldevs: %s\n", errbuf);
		return NULL;
	}

	fprintf(stdout, "Available interfaces:\n");
	for (d = alldevs, i = 0; d != NULL; d = d->next) {
		fprintf(stdout, "%d.  %s\n", ++i, d->name);
		if (d->description)
			fprintf(stdout, "  %s\n", d->description);
		else
			fprintf(stdout, "  No description available\n");
	}

	if (i == 0) {
		pcap_freealldevs(alldevs);
		snprintf(in_err, 1024, "No interfaces found, are WinPcap and AirPcap "
				 "installed and the AirPcap device attached?");
		return NULL;
	}

	while (1) {
		fprintf(stdout, "Enter interface number (1-%d):", i);
		if (fscanf(stdin, "%d", &intnum) != 1) {
			fprintf(stdout, "Invalid entry\n");
			continue;
		}

		if (intnum < 1 || intnum > i) {
			fprintf(stdout, "Invalid entry, must be between 1 and %d\n", i);
			continue;
		}

		break;
	}

	// Find the adapter
	for (d = alldevs, i = 0; i < intnum - 1; d = d->next, i++) 
		;

	src = new AirPcapSource(in_name, string(d->name));

	pcap_freealldevs(alldevs);

	return src;
}

int chancontrol_airpcap(const char *in_dev, int in_ch, char *in_err, void *in_ext) {
	// Channel control uses the external pointer
	return ((AirPcapSource *) in_ext)->SetChannel(in_ch, in_err);
}

#endif

