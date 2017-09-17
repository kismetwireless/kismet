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

#ifndef __DATASTORE_H__
#define __DATASTORE_H__

#include "config.h"

/* Generic data store based on sqlite3 */

#include <memory>

#include <stdio.h>
#include <sqlite3.h>

#include "globalregistry.h"

class Datastore : public LifetimeGlobal {
public:
    static shared_ptr<Datastore> create_datastore(GlobalRegistry *in_globalreg) {
        shared_ptr<Datastore> mon(new Datastore(in_globalreg));
        in_globalreg->RegisterLifetimeGLobal(mon);
        in_globalreg->InsertGlobal("DATASTORE", mon);
        return mon;
    }

private:
    Datastore(GlobalRegistry *in_globalreg);

public:
    virtual ~Datastore();

};


#endif


