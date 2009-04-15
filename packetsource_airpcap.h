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

/* Ported from the kismet-stable airpcap source, contrbuted by Loris of CACE
 */

#ifndef __PACKETSOURCE_AIRPCAP_H__
#define __PACKETSOURCE_AIRPCAP_H__

#include "config.h"

#if defined(HAVE_LIBPCAP) && defined(HAVE_LIBAIRPCAP) && defined(SYS_CYGWIN)

// This is a bad thing to do, but windows.h totally breaks c++ strings,
// which is also unacceptable.

extern "C" {
// Some Windows-specific definitions. They are normally imported by 
// including windows.h, but we don't do it because of conflicts with the 
// rest of cygwin
typedef unsigned int		ULONG, *PULONG;
typedef int					LONG, *PLONG;
typedef unsigned int		UINT, *PUINT;
typedef int					INT, *PINT;
typedef int					BOOL, *PBOOL;
typedef unsigned short		USHORT, *PUSHORT;
typedef short				SHORT, *PSHORT;
typedef unsigned char		UCHAR, *PUCHAR;
typedef signed char			CHAR, *PCHAR;
typedef unsigned char		BYTE, *PBYTE;
typedef void				VOID, *PVOID;
typedef void				*HANDLE;
typedef unsigned long long	ULONGLONG, *PULONGLONG;

#include <airpcap.h>
}

#include "cygwin_utils.h"

#include "packet.h"
#include "packet_ieee80211.h"
#include "packetsource.h"
#include "packetsource_pcap.h"

#ifdef HAVE_LOCALRADIOTAP
#include "local_ieee80211_radiotap.h"
#endif

#define USE_PACKETSOURCE_AIRPCAP

// Another pcap variant, with some local overriding hooks
class PacketSource_AirPcap : public PacketSource_Pcap {
public:
	PacketSource_AirPcap() {
		fprintf(stderr, "FATAL OOPS:  Packetsource_Airpcap() called\n");
		exit(1);
	}

	PacketSource_AirPcap(GlobalRegistry *in_globalreg) :
		PacketSource_Pcap(in_globalreg) {

	}

	virtual KisPacketSource *CreateSource(GlobalRegistry *in_globalreg,
										  string in_interface,
										  vector<opt_pair> *in_opts) {
		return new PacketSource_AirPcap(in_globalreg, in_interface, in_opts);
	}

	virtual int AutotypeProbe(string in_device);
	virtual int RegisterSources(Packetsourcetracker *tracker);

	PacketSource_AirPcap(GlobalRegistry *in_globalreg, string in_interface,
						 vector<opt_pair> *in_opts);

	virtual ~PacketSource_AirPcap() { }

	virtual int OpenSource();

	virtual int Poll();

	virtual int FetchDescriptor();

	virtual int FetchChannelCapable() { return 1; }

	virtual int EnableMonitor();
	virtual int DisableMonitor();
	virtual int SetChannel(unsigned int in_ch);
	virtual int FetchHardwareChannel();

	virtual vector<unsigned int> FetchSupportedChannels(string in_interface);

protected:
	virtual void FetchRadioData(kis_packet *in_packet) { };

	PAirpcapHandle airpcap_handle;
	HANDLE winpcap_evthandle;
	Handle2Fd fd_mangle;
};

#endif /* cygwin */

#endif

