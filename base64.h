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

#include <stdlib.h>
#include <sstream>

#ifndef __BASE64_H__
#define __BASE64_H__

/* Unexciting base64 implementation 
 * Needed to handle b64 encoded post data for the webserver
 */

class Base64 {
public:
    /* Decode a string; return true if it was valid */
    static string decode(string in_str);

    // Convert 4 6-bit b64 characters into 3 8-bit standard bytes.
    // In and out must be able to hold the appropriate amount of data.
    static void decodeblock(unsigned char *in, unsigned char *out);

protected:
    const static char b64_values[];
};

#endif

