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

#include <config.h>
#include <string>
#include <errno.h>
#include <time.h>

#include <pthread.h>

#include <sstream>
#include <iomanip>

#include <util.h>
#include <messagebus.h>
#include <packet.h>
#include <packetchain.h>
#include <packetsource.h>
#include <packetsourcetracker.h>
#include <timetracker.h>
#include <configfile.h>
#include <plugintracker.h>
#include <globalregistry.h>
#include <netracker.h>
#include <dumpfile_pcap.h>
#include <kis_ppi.h>
#include <endian_magic.h>
#include <version.h>

#include "spectool_netclient.h"

typedef struct {
	uint16_t pfh_datatype;
	uint16_t pfh_datalen;
	uint32_t start_khz;
	uint32_t res_hz;
	uint32_t amp_offset_mdbm;
	uint32_t amp_res_mdbm;
	uint16_t rssi_max;
	uint16_t num_samples;
	uint8_t data[0];
} ppi_spectrum;

GlobalRegistry *globalreg = NULL;
SpectoolsClient *stc = NULL;
int pcm_specdata;

int kisspec_dump(DUMPFILE_PPI_PARMS) {
	int ppi_pos;
	kis_spectrum_data *specdata =
		(kis_spectrum_data *) in_pack->fetch(pcm_specdata);

	if (specdata == NULL) {
		// Don't reset us to position 0 if data is missing and we've got a
		// position set to dump do (this means we're logging data, but not
		// in this packet!)
		if (dump_pos != 0)
			return dump_pos;

		return 0;
	}

	if (in_allocate)  {
		return sizeof(ppi_spectrum) + specdata->rssi_vec.size();
	}

	ppi_spectrum *ppi_spec;
	ppi_spec = (ppi_spectrum *) &(dump_data[dump_pos]);
	ppi_pos += sizeof(ppi_spectrum) + specdata->rssi_vec.size();

	ppi_spec->pfh_datatype = kis_htole16(PPI_FIELD_SPECMAP);
	ppi_spec->pfh_datalen = kis_htole16(sizeof(ppi_spectrum) -
										sizeof(ppi_field_header) +
										specdata->rssi_vec.size());

	ppi_spec->start_khz = kis_htole32(specdata->start_khz);
	ppi_spec->res_hz = kis_htole32(specdata->res_hz);
	ppi_spec->amp_offset_mdbm = kis_htole32(abs(specdata->amp_offset_mdbm));
	ppi_spec->amp_res_mdbm = kis_htole32(specdata->amp_res_mdbm);
	ppi_spec->rssi_max = kis_htole16(specdata->rssi_max);
	ppi_spec->num_samples = kis_htole16(specdata->rssi_vec.size());
	for (unsigned int s = 0; s < specdata->rssi_vec.size(); s++) 
		ppi_spec->data[s] = specdata->rssi_vec[s];

	return ppi_pos;
}

int kisspec_register(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;

	if (globalreg->kismet_instance != KISMET_INSTANCE_SERVER) {
		_MSG("Not activating SPECTOOLS plugin, not running on a server",
			 MSGFLAG_INFO);
		return 1;
	}

	if (globalreg->pcapdump == NULL || globalreg->packetchain == NULL ||
		globalreg->kismet_config == NULL || globalreg->kisnetserver == NULL) 
		return 0;

	stc = new SpectoolsClient(globalreg);
	pcm_specdata = stc->FetchPacketCompId();
	globalreg->pcapdump->RegisterPPICallback(kisspec_dump, NULL);

	return 1;
}

int kisspec_unregister(GlobalRegistry *in_globalreg) {
	if (stc != NULL)
		delete stc;
	if (globalreg->pcapdump != NULL)
		globalreg->pcapdump->RemovePPICallback(kisspec_dump, NULL);
}

extern "C" {
	int kis_plugin_info(plugin_usrdata *data) {
		data->pl_name = "SPECTOOL";
		data->pl_version = string(VERSION_MAJOR) + "-" + string(VERSION_MINOR) + "-" +
			string(VERSION_TINY);
		data->pl_description = "Spectool-Net";
		data->pl_unloadable = 0; 
		data->plugin_register = kisspec_register;
		data->plugin_unregister = kisspec_unregister;

		return 1;
	}

	void kis_revision_info(plugin_revision *prev) {
		if (prev->version_api_revision >= 1) {
			prev->version_api_revision = 1;
			prev->major = string(VERSION_MAJOR);
			prev->minor = string(VERSION_MINOR);
			prev->tiny = string(VERSION_TINY);
		}
	}
}

