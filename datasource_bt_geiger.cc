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
#include "datasource_bt_geiger.h"

kis_datasource_bt_geiger::kis_datasource_bt_geiger(shared_datasource_builder in_builder) :
    kis_datasource(in_builder) {

    auto devmac = munge_to_printable(get_definition_opt("device"));
    if (devmac != "") {
        set_int_source_cap_interface(fmt::format("btgeiger_{}", devmac));
    } else {
        set_int_source_cap_interface("btgeiger");
    }

    set_int_source_hardware("btgeiger");
    set_int_source_ipc_binary("kismet_cap_bt_geiger");
}

kis_datasource_bt_geiger::~kis_datasource_bt_geiger() {

}

void kis_datasource_bt_geiger::open_interface(std::string in_definition, unsigned int in_transaction,
        open_callback_t in_cb) {
    kis_datasource::open_interface(in_definition, in_transaction, in_cb);
}

