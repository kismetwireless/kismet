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

#include "packet.h"
#include "packetsource.h"
#include "pcapsource.h"

extern "C" {
#include <airpcap.h>
}

class AirPcapSource : public PcapSource {
public:
    AirPcapSource(string in_name, string in_dev) : PcapSource(in_name, in_dev) { 
    }
    virtual int FetchChannel();
	virtual int SetChannel(unsigned int in_ch, char *in_err);

protected:
    virtual int FetchSignalLevels(int *in_siglev, int *in_noiselev);
	PAircapHandle airpcap_handle;
};

KisPacketSource *airpcapsource_registrant(string in_name, string in_device,
										  char *in_err);
KisPacketSource *airpcapsourceq_registrant(string in_name, string in_device,
										   char *in_err);
int chancontrol_airpcap(const char *in_dev, int in_ch, char *in_err, void *in_ext);

#endif

#endif

