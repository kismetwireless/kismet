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

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#ifdef HAVE_LINUX_WIRELESS
// Because some kernels include ethtool which breaks horribly...
// The stock ones don't but others seem to
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

#include <linux/wireless.h>
#endif

#include "util.h"
#include "packetsourcetracker.h"
#include "packetsource_wext.h"

#if (defined(HAVE_LIBPCAP) && defined(SYS_LINUX) && defined(HAVE_LINUX_WIRELESS))

int PacketSource_Wext::FetchChannel() {
    char errstr[STATUS_MAX] = "";

    // Failure to fetch a channel isn't necessarily a fatal error
	// and if we blow up badly enough that we can't get channels, we'll
	// blow up definitively on something else soon enough
    if (Iwconfig_Get_Channel(interface.c_str(), errstr) < 0) {
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

    return 1;
}

void PacketSource_Wext::FetchRadioData(kis_packet *in_packet) {
	// Build a signal layer record if we don't have one from the builtin headers.
	// These are less accurate.
	char errstr[STATUS_MAX] = "";
	int ret;
	
	kis_layer1_packinfo *radiodata = (kis_layer1_packinfo *) 
		in_packet->fetch(_PCM(PACK_COMP_RADIODATA));

	// We don't do anything if we have a signal layer from anywhere else
	if (radiodata == NULL)
		radiodata = new kis_layer1_packinfo;
	else
		return;

	// Fetch the signal levels if we know how and it hasn't been already.
	// Blow up if we can't, but do so sanely
	if ((ret = Iwconfig_Get_Levels(interface.c_str(), errstr,
								   &(radiodata->signal), &(radiodata->noise))) < 0) {
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		delete radiodata;
		return;
	}

	// Fetch the channel if we know how and it hasn't been filled in already
	radiodata->channel = FetchChannel();

	// Low accuracy
	radiodata->accuracy = 1;

	// If we didn't get anything good, destroy it
	if (radiodata->signal == 0 && radiodata->noise == 0 && radiodata->channel == 0) {
		delete radiodata;
		return;
	}

	in_packet->insert(_PCM(PACK_COMP_RADIODATA), radiodata);
}

/* *********************************************************** */
/* Packetsource registrant functions */

KisPacketSource *packetsource_wext_registrant(REGISTRANT_PARMS) {
	return new PacketSource_Wext(globalreg, in_name, in_device);
}

KisPacketSource *packetsource_wext_fcs_registrant(REGISTRANT_PARMS) {
	PacketSource_Wext *ret = new PacketSource_Wext(globalreg, in_name, in_device);
	ret->SetFCSBytes(4);
	return ret;
}

KisPacketSource *packetsource_wext_split_registrant(REGISTRANT_PARMS) {
    char errstr[STATUS_MAX] = "";

    vector<string> devbits = StrTokenize(in_device, ":");

    if (devbits.size() < 2) {
        snprintf(errstr, STATUS_MAX, "Invalid device pair '%s'", in_device.c_str());
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		globalreg->fatal_condition = 1;
        return NULL;
    }

    return new PacketSource_Wext(globalreg, in_name, devbits[1]);
}

KisPacketSource *packetsource_wext_splitfcs_registrant(REGISTRANT_PARMS) {
	KisPacketSource *psrc = 
		packetsource_wext_split_registrant(globalreg, in_name, in_device);
	psrc->SetFCSBytes(4);
	return psrc;
}

/* *********************************************************** */
/* Monitor enter/exit functions */

int monitor_wext_core(MONITOR_PARMS, char *errstr) {
	linux_ifparm *ifparm = (linux_ifparm *) malloc(sizeof(linux_ifparm));

	if (Ifconfig_Get_Flags(in_dev, errstr, &ifparm->flags) < 0) {
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		snprintf(errstr, STATUS_MAX, "Failed to get interface flags for %s, "
				 "this will probably fully fail in a moment when we try to "
				 "configure the interface, but we'll try anyhow.", in_dev);
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
	}

	// Bring the interface up, zero its IP, etc
	if (Ifconfig_Delta_Flags(in_dev, errstr, 
							 IFF_UP | IFF_RUNNING | IFF_PROMISC) < 0) {
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
		snprintf(errstr, STATUS_MAX, "Failed bringing interface %s up, check "
				 "your permissions and configuration and consult the README "
				 "file.", in_dev);
		free(ifparm);
		return -1;
	}

	// Try to grab the channel
	if ((ifparm->channel = Iwconfig_Get_Channel(in_dev, errstr)) < 0) {
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		snprintf(errstr, STATUS_MAX, "Failed to get current channel for %s. "
				 "This will probably fail in a moment when we try to set the "
				 "card mode and channel, but we'll keep going incase the "
				 "drivers are reporting incorrectly.", in_dev);
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		ifparm->channel = -1;
	}

	// Try to grab the wireless mode
	if (Iwconfig_Get_Mode(in_dev, errstr, &(ifparm->mode)) < 0) {
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		snprintf(errstr, STATUS_MAX, "Failed to get current wireless modes for "
				 "%s, check your configuration and consult the README "
				 "file.", in_dev);
		free(ifparm);
		return -1;
	}

	// Set it to monitor mode if we need to
	if (ifparm->mode != LINUX_WLEXT_MONITOR) {
		if (Iwconfig_Set_Mode(in_dev, errstr, LINUX_WLEXT_MONITOR) < 0) {
			globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
			snprintf(errstr, STATUS_MAX, "Failed to set monitor mode on interface "
					 "%s.  This usually means your drivers either do not "
					 "support monitor mode, or use a different mechanism to set "
					 "monitor mode.  Make sure you have a version of your drivers "
					 "that supports monitor mode (this may require patching or "
					 "other special configuration of the driver source) and that "
					 "you have configured the correct capture source inside "
					 "Kismet.  Consult the troubleshooting section of the README "
					 "for more information.", in_dev);
			free(ifparm);
			return -1;
		}
	} else {
		snprintf(errstr, STATUS_MAX, "Interface %s appears to already be in "
				 "monitor mode, leaving it as it is.", in_dev);
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
	}

	(*in_if) = ifparm;
	
	// Set the initial channel
	if (chancontrol_wext_std(globalreg, in_dev, initch, NULL) < 0) {
		return -2;
	}

	return 0;
}

int unmonitor_wext_core(MONITOR_PARMS, char *errstr) {
	linux_ifparm *ifparm = (linux_ifparm *) (*in_if);

	if (ifparm == NULL)
		return 1;

	// We don't care if this fails
	chancontrol_wext_std(globalreg, in_dev, ifparm->channel, NULL);

	// We do care if this fails
	if (Iwconfig_Set_Mode(in_dev, errstr, ifparm->mode) < 0) {
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		snprintf(errstr, STATUS_MAX, "Failed to set wireless mode to stored value "
				 "for %s.  It may be left in an unusable state.", in_dev);
		free(ifparm);
		return -1;
	}

	if (Ifconfig_Set_Flags(in_dev, errstr, ifparm->flags) < 0) {
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		snprintf(errstr, STATUS_MAX, "Failed to set interface flags to stored value "
				 "for %s.  It may be left in an unusable state.", in_dev);
		free(ifparm);
		return -1;
	}

	free(ifparm);
	return 1;
}

int monitor_wext_std(MONITOR_PARMS) {
	char errstr[STATUS_MAX];

	// Fall through to the primary monitor functon
	if (monitor_wext_core(globalreg, in_dev, initch, in_if, in_ext, errstr) < 0) {
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	return 1;
}

int unmonitor_wext_std(MONITOR_PARMS) {
	char errstr[STATUS_MAX];

	// Fall through to the primary monitor functon
	if (unmonitor_wext_core(globalreg, in_dev, initch, in_if, in_ext, errstr) < 0) {
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	return 1;
}


int chancontrol_wext_core(CHCONTROL_PARMS, char *errstr) {
    if (Iwconfig_Set_Channel(in_dev, in_ch, errstr) < 0) {
        return -1;
    }

    return 1;
}

int chancontrol_wext_std(CHCONTROL_PARMS) {
	char errstr[STATUS_MAX];

	if (chancontrol_wext_core(globalreg, in_dev, in_ch, in_ext, errstr) < 0) {
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return -1;
	}

	return 1;
}

#endif

