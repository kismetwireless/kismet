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

// pcapsource is probably the most complex source handing the largest number of
// card types.  Ideally, everything should be part of the pcap source except
// wsp100 and drones.

#ifndef __AIRPCAPSOURCE_H__
#define __AIRPCAPSOURCE_H__

#include "config.h"

#if defined(HAVE_LIBPCAP) && defined(HAVE_LIBAIRPCAP) && defined(SYS_CYGWIN)

#include "pcapsource.h"

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

#include <airpcap.h>
}

#include "cygwin_utils.h"

class AirPcapSource : public PcapSource {
public:
    AirPcapSource(string in_name, string in_dev) : PcapSource(in_name, in_dev) { 
    }
	virtual int OpenSource();
	virtual int FetchPacket(kis_packet *packet, uint8_t *data, uint8_t *moddata);
	virtual int FetchChannel();
	virtual int FetchDescriptor();
	virtual int SetChannel(unsigned int in_ch, char *in_err);

protected:
    virtual int FetchSignalLevels(int *in_siglev, int *in_noiselev);
	PAirpcapHandle airpcap_handle;
	HANDLE winpcap_evthandle;
	Handle2Fd fd_mangle;
};

KisPacketSource *airpcapsource_registrant(string in_name, string in_device,
										  char *in_err);
KisPacketSource *airpcapsourceq_registrant(string in_name, string in_device,
										   char *in_err);
int chancontrol_airpcap(const char *in_dev, int in_ch, char *in_err, void *in_ext);

#endif

#endif

