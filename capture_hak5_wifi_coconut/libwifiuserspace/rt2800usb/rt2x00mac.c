// SPDX-License-Identifier: GPL-2.0-or-later
/*
	Copyright (C) 2004 - 2009 Ivo van Doorn <IvDoorn@gmail.com>
	<http://rt2x00.serialmonkey.com>

 */

/*
 * Userspace port (c) 2019 Hak5
 */

/*
	Module: rt2x00mac
	Abstract: rt2x00 generic mac80211 routines.
 */

#include <errno.h>

#include "kernel/ieee80211.h"
#include "kernel/kernel.h"

#include "rt2800usb/rt2x00.h"
#include "rt2800usb/rt2x00lib.h"

int rt2x00mac_start(struct ieee80211_hw *hw)
{
	struct rt2x00_dev *rt2x00dev = (struct rt2x00_dev *) hw->priv;

	if (!test_bit(DEVICE_STATE_PRESENT, &rt2x00dev->flags))
		return 0;

	return rt2x00lib_start(rt2x00dev);
}
EXPORT_SYMBOL_GPL(rt2x00mac_start);

void rt2x00mac_stop(struct ieee80211_hw *hw)
{
	struct rt2x00_dev *rt2x00dev = (struct rt2x00_dev *) hw->priv;

	if (!test_bit(DEVICE_STATE_PRESENT, &rt2x00dev->flags))
		return;

	rt2x00lib_stop(rt2x00dev);
}
EXPORT_SYMBOL_GPL(rt2x00mac_stop);

int rt2x00mac_add_interface(struct ieee80211_hw *hw,
			    struct ieee80211_vif *vif)
{
	struct rt2x00_dev *rt2x00dev = (struct rt2x00_dev *) hw->priv;
	struct rt2x00_intf *intf = vif_to_intf(vif);

	/*
	 * Don't allow interfaces to be added
	 * the device has disappeared.
	 */
	if (!test_bit(DEVICE_STATE_PRESENT, &rt2x00dev->flags) ||
	    !test_bit(DEVICE_STATE_STARTED, &rt2x00dev->flags)) {
        rt2x00_err(rt2x00dev, "Device not started before adding vif\n");
		return -ENODEV;
    }

	/*
	 * We are now absolutely sure the interface can be created,
	 * increase interface count and start initialization.
	 */

	/*
	 * The MAC address must be configured after the device
	 * has been initialized. Otherwise the device can reset
	 * the MAC registers.
	 * The BSSID address must only be configured in AP mode,
	 * however we should not send an empty BSSID address for
	 * STA interfaces at this time, since this can cause
	 * invalid behavior in the device.
	 */
	rt2x00lib_config_intf(rt2x00dev, intf, vif->type,
			      vif->addr, NULL);

	return 0;
}
EXPORT_SYMBOL_GPL(rt2x00mac_add_interface);

void rt2x00lib_config_intf(struct rt2x00_dev *rt2x00dev,
			   struct rt2x00_intf *intf,
			   enum nl80211_iftype type,
			   const u8 *mac, const u8 *bssid)
{

    /*
     * Trimmed down for userspace 
     */

	struct rt2x00intf_conf conf;
	unsigned int flags = 0;

	conf.type = type;

	switch (type) {
	case NL80211_IFTYPE_ADHOC:
		conf.sync = TSF_SYNC_ADHOC;
		break;
	case NL80211_IFTYPE_AP:
	case NL80211_IFTYPE_MESH_POINT:
	case NL80211_IFTYPE_WDS:
		conf.sync = TSF_SYNC_AP_NONE;
		break;
	case NL80211_IFTYPE_STATION:
		conf.sync = TSF_SYNC_INFRA;
		break;
	default:
		conf.sync = TSF_SYNC_NONE;
		break;
	}

    flags = CONFIG_UPDATE_TYPE | CONFIG_UPDATE_MAC | CONFIG_UPDATE_BSSID;

	rt2x00dev->ops->lib->config_intf(rt2x00dev, intf, &conf, flags);
}

