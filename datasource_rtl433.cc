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
#include "kis_datasource.h"
#include "datasource_rtl433.h"

KisDatasourceRtl433::KisDatasourceRtl433(GlobalRegistry *in_globalreg,
        SharedDatasourceBuilder in_builder) :
    KisDatasource(in_globalreg, in_builder),
    Kis_Net_Httpd_CPPStream_Handler(in_globalreg) {

}

KisDatasourceRtl433::~KisDatasourceRtl433() {

}

bool KisDatasourceRtl433::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "GET") == 0) {
        if (!Httpd_CanSerialize(path))
            return false;

        std::string stripped = Httpd_StripSuffix(path);
        std::vector<std::string> tokenurl = StrTokenize(stripped, "/");

        if (tokenurl.size() < 5)
            return false;

        if (tokenurl[1] != "datasource")
            return false;

        if (tokenurl[2] != "by-uuid")
            return false;

        if (tokenurl[3] != get_source_uuid().UUID2String())
            return false;

        if (tokenurl[4] == "test")
            return true;
    }

    return false;
}

void KisDatasourceRtl433::Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
        Kis_Net_Httpd_Connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size, std::stringstream &stream) {

    if (strcmp(method, "GET") == 0) {
        std::string stripped = Httpd_StripSuffix(url);
        std::vector<std::string> tokenurl = StrTokenize(stripped, "/");

        if (tokenurl.size() < 5)
            return;

        if (tokenurl[1] != "datasource")
            return;

        if (tokenurl[2] != "by-uuid")
            return;

        if (tokenurl[3] != get_source_uuid().UUID2String())
            return;

        if (tokenurl[4] == "test") {
            stream << "Hi!";
            return;
        }
    }

}


