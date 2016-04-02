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

#ifndef __DARWIN_CONTROL_OBJC_H__
#define __DARWIN_CONTROL_OBJC_H__

#include "config.h"

#ifdef SYS_DARWIN

int darwin_bcom_testmonitor();
int darwin_bcom_enablemonitorfile(const char *c_filename);
int darwin_bcom_enablemonitor();

void *darwin_allocate_interface(const char *in_iface);
void darwin_free_interface(void *in_darwin);

int darwin_get_channels(const char *in_iface, int **ret_channels);
int darwin_set_channel(unsigned int in_channel, char *ret_err, void *in_darwin);

void darwin_disassociate(void *in_darwin);

int darwin_get_corewifi(void *in_darwin);

#endif

#endif

