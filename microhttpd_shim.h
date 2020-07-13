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

#ifndef __MICROHTTPD_SHIM_H__
#define __MICROHTTPD_SHIM_H__ 

// Microhttpd changed their basic API in a breaking way; this patches around it.

#include <microhttpd.h>

#if MHD_VERSION >= 0x00097002
#define KIS_MHD_RETURN enum MHD_Result
#else
#define KIS_MHD_RETURN int
#endif


#endif /* ifndef MICROHTTPD_SHIM_H */
