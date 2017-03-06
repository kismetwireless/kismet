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
#include "text_cliframe.h"

TextCliFrame::TextCliFrame(GlobalRegistry *in_globalreg) : 
	ClientFramework(in_globalreg) {
	netclient = NULL;
	next_id = 0;

}

TextCliFrame::~TextCliFrame() {
	if (globalreg != NULL) {
		globalreg->RemovePollableSubsys(this);
	}
}

void TextCliFrame::RegisterNetworkClient(NetworkClient *in_netc) {
	netclient = in_netc;
	netclient->RegisterClientFramework(this);
}

int TextCliFrame::RegisterCallback(textcli_cb in_cb, void *in_aux) {
	textcli_cb_s cbs;

	cbs.id = next_id++;
	cbs.cb = in_cb;
	cbs.auxptr = in_aux;

	callback_vec.push_back(cbs);

	return cbs.id;
}

void TextCliFrame::RemoveCallback(int in_id) {
	for (unsigned int x = 0; x < callback_vec.size(); x++) {
		if (callback_vec[x].id == in_id) {
			callback_vec.erase(callback_vec.begin() + x);
			return;
		}
	}
}

// static int debug_lineno = 0;

int TextCliFrame::ParseData() {
	int len, rlen = 0, roft = 0;
	char *buf;
	string strbuf;

	len = netclient->FetchReadLen();
	buf = new char[len + 1];

	if (netclient->ReadData(buf, len, &rlen) < 0) {
		_MSG("Textclient::Parsedata failed to fetch data", MSGFLAG_ERROR);
    delete[] buf;
		return -1;
	}

	if (rlen <= 0)
		return 0;

	buf[rlen] = '\0';

    // Parse without including partials, so we don't get a fragmented command 
    // out of the buffer
    vector<string> inptok = StrTokenize(buf + roft, "\n", 0);
    delete[] buf;

    // Bail on no useful data
    if (inptok.size() <= 0) {
        return 0;
    }

	for (unsigned int it = 0; it < inptok.size(); it++) {
		netclient->MarkRead(inptok[it].length() + 1 + roft);
		inptok[it] = StrPrintable(inptok[it]);
		// inptok[it] = IntToString(debug_lineno++) + " " + StrPrintable(inptok[it]);

		for (unsigned int c = 0; c < callback_vec.size(); c++) {
			(*callback_vec[c].cb)(inptok[it], callback_vec[c].auxptr);
		}
	}

	return 1;
}

