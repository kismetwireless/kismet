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
#include "datasource_cell_diag.h"

kis_datasource_cell_diag::kis_datasource_cell_diag(shared_datasource_builder in_builder) :
    kis_datasource(in_builder) {

    std::string devpath = munge_to_printable(get_definition_opt("device"));
    if (devpath != "") {
        set_int_source_cap_interface("celldiag#" + devpath);
    } else {
        set_int_source_cap_interface("celldiag");
    }

    set_int_source_hardware("celldiag");
    set_int_source_ipc_binary("kismet_cap_cell_diag");
}

kis_datasource_cell_diag::~kis_datasource_cell_diag() {

}

void kis_datasource_cell_diag::open_interface(std::string in_definition, unsigned int in_transaction,
        open_callback_t in_cb) {
    kis_datasource::open_interface(in_definition, in_transaction, in_cb);
}
