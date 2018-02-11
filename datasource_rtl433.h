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

#ifndef __DATASOURCE_RTL433_H__
#define __DATASOURCE_RTL433_H__

#include "config.h"

#include "kis_datasource.h"
#include "kis_net_microhttpd.h"

/* A light-weight HTTP based data source which receives JSON-encoded
 * sensor data from the rtl433 tool.
 *
 * Device records are received from the rtl433 capture tool via the kismet
 * rest interface, placed into a packet, and decoded by the phy
 */

class KisDatasourceRtl433;
typedef std::shared_ptr<KisDatasourceRtl433> SharedDatasourceRtl433;

class KisDatasourceRtl433 : public KisDatasource, public Kis_Net_Httpd_CPPStream_Handler {
public:
    KisDatasourceRtl433(GlobalRegistry *in_globalreg, SharedDatasourceBuilder in_builder);
    virtual ~KisDatasourceRtl433();

    virtual bool Httpd_VerifyPath(const char *path, const char *method);

    virtual void Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream);

    virtual int Httpd_PostComplete(Kis_Net_Httpd_Connection *concls);

protected:
    int pack_comp_rtl433;

};

class DatasourceRtl433Builder : public KisDatasourceBuilder {
public:
    DatasourceRtl433Builder(GlobalRegistry *in_globalreg, int in_id) :
        KisDatasourceBuilder(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    DatasourceRtl433Builder(GlobalRegistry *in_globalreg, int in_id,
        SharedTrackerElement e) :
        KisDatasourceBuilder(in_globalreg, in_id, e) {

        register_fields();
        reserve_fields(e);
        initialize();
    }

    DatasourceRtl433Builder(GlobalRegistry *in_globalreg) :
        KisDatasourceBuilder(in_globalreg, 0) {

        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    virtual ~DatasourceRtl433Builder() { }

    virtual SharedDatasource build_datasource(SharedDatasourceBuilder in_sh_this) {
        return SharedDatasourceRtl433(new KisDatasourceRtl433(globalreg, in_sh_this));
    }

    virtual void initialize() {
        set_source_type("rtl433");
        set_source_description("rtl433-captured sensor data over http");

        set_probe_capable(false);
        set_list_capable(false);
        set_local_capable(true);
        set_remote_capable(true);
        set_passive_capable(true);
        set_tune_capable(false);
    }
};

#endif


