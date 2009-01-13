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

#ifndef __TEXTCLIFRAME_H__
#define __TEXTCLIFRAME_H__

#include "config.h"

#include "clinetframework.h"

#define TEXTCLI_PARMS	string text, void *auxptr
typedef void (*textcli_cb)(TEXTCLI_PARMS);

class TextCliFrame : public ClientFramework {
public:
	TextCliFrame() { fprintf(stderr, "FATAL OOPS:  TextCliFrame()\n"); }
	TextCliFrame(GlobalRegistry *in_globalreg);
	virtual ~TextCliFrame();

	int ParseData();

    void RegisterNetworkClient(NetworkClient *in_netc);

	int RegisterCallback(textcli_cb in_cb, void *in_aux);
	void RemoveCallback(int in_id);

	struct textcli_cb_s {
		int id;
		textcli_cb cb;
		void *auxptr;
	};

protected:
	int next_id;
	vector<textcli_cb_s> callback_vec;
};

#endif

