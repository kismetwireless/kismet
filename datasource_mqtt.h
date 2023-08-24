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

#ifndef __DATASOURCE_MQTT_H__
#define __DATASOURCE_MQTT_H__

#include "config.h"

#include "kis_datasource.h"


#ifdef HAVE_LIBMOSQUITTO

class kis_datasource_mqtt : public kis_datasource {
public:
    kis_datasource_mqtt(shared_datasource_builder in_builder);
    virtual ~kis_datasource_mqtt();

protected:
    virtual void open_interface(std::string in_definition, unsigned int in_transaction,
            open_callback_t in_cb) override;
};

#else /* HAVE_LIBMOSQUITTO */

class kis_datasource_mqtt : public kis_datasource {
public:
    kis_datasource_mqtt(shared_datasource_builder in_builder);
    virtual ~kis_datasource_mqtt();

protected:
    virtual void open_interface(std::string in_definition, unsigned int in_transaction,
            open_callback_t in_cb) override;
};

#endif

#endif /* __DATASOURCE_MQTT_H__ */
