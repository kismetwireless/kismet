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

#ifndef __VIHASOURCE_H__
#define __VIHASOURCE_H__

#include "config.h"

#ifdef HAVE_VIHAHEADERS

#include "packetsource.h"

#include <pthread.h>
#include <sys/types.h>
#include <unistd.h>

#include <WiFi/WLPacketSource.h>
#include <WiFi/WLFrame.h>
#include <WiFi/IEEE80211Frame.h>
#include <WiFi/WFException.h>

class VihaSource : public KisPacketSource {
public:
    VihaSource(GlobalRegistry *in_globalreg, string in_name, 
               string in_dev) : KisPacketSource(in_globalreg, in_name, in_dev) { }

    int OpenSource();

    int CloseSource();

    int FetchChannel();

    int FetchDescriptor() { return pipe_fds[0]; }

    int FetchPacket(kis_packet *packet, uint8_t *data, uint8_t *moddata);

protected:
    int LocalSetChannel(int in_ch, char *in_err);
    
    WLFrame *frame;
    WLPacketSource *wlsource;
    WLDriverInterface* wldi;
    int pipe_fds[2];
    
    int Viha2Common(kis_packet *packet, uint8_t *data, uint8_t *moddata);

    pthread_mutex_t capture_lock;
    pthread_cond_t capture_wait;
    int frame_full;

    friend void *ReadPacketLoop(void *arg);
    friend int chancontrol_viha(const char *in_dev, int in_ch, char *in_err, 
                                void *in_ext);
};

// We don't need a monitor function since loading the viha drivers puts us
// into monitormode automatically
KisPacketSource *vihasource_registrant(REGISTRANT_PARMS);
int chancontrol_viha(CHCONTROL_PARMS);

#endif /* HAVE_VIHAHEADERS */

#endif /* __VIHASOURCE_H__ */
