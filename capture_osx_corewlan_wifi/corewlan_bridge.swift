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

/* This bridges Swift corewlan code to the Kismet C capturesource code.
   There's some jankiness converting arrays - I don't know much Swift.
   Fortunately this only happens once.

   @_silgen_name causes swift to generate C namespaced functions.

   */

import Cocoa
import CoreFoundation
import CoreWLAN

/* Global copies */
var channels = [String : [CWChannel]]();
var native_interfaces = [String : CWInterface]();
var interfaces = [String]();

/* Enumerate the corewlan items and put them in our local variables */
@_silgen_name("corewlan_init")
public func corewlan_init() -> Int
{
    /* There is almost certainly a smarter way to do this, but we are
       not swift programmers.  Patches definitely welcome. */
    if #available(OSX 10.10, *) {
        let wf = CWWiFiClient()
            let interfs = [wf!.interfaces()]
            let interfenum = interfs.enumerated()

            for (_, intfs) in interfenum {
                for intf in intfs! {
                    let intname = intf.interfaceName!
                    interfaces.append(intname)
		            native_interfaces[intname] = intf
                    let chans = [intf.supportedWLANChannels()]
                    let enumchans = chans.enumerated()

                    var ichans = [CWChannel]();
                    for (_, chanblob) in enumchans{
                        for channel in chanblob! {
				            ichans.append(channel)
                        }
                    }
                    channels[intname] = ichans
                }
            }
        return 1;
    } else {
        return -1;
    }

}

/* How many interfaces do we have? */
@_silgen_name("corewlan_num_interfaces")
public func corewlan_num_interfaces() -> Int
{
    return interfaces.count;
}

/* Get a single interface */
@_silgen_name("corewlan_get_interface")
public func corewlan_get_interface(pos : Int) -> UnsafePointer<Int8>
{
    return UnsafePointer<Int8>(strdup(interfaces[pos]));
}

/* Get number of channels */
@_silgen_name("corewlan_num_channels")
public func corewlan_num_channels(intf : String) -> Int
{
    return channels[intf]!.count;
}

@_silgen_name("corewlan_get_channel")
public func corewlan_get_channel(intf : String, pos : Int) -> Int
{
    return channels[intf]![pos].channelNumber;
}

@_silgen_name("corewlan_get_channel_width")
public func corewlan_get_channel_width(intf : String, pos : Int) -> Int
{
    return channels[intf]![pos].channelWidth.rawValue;
}

@_silgen_name("corewlan_find_channel")
public func corewlan_find_channel(intf : String, channel : Int, width : Int) -> Int
{
    for (index, c) in channels[intf]!.enumerated() {
        if (c.channelNumber == channel && c.channelWidth.rawValue == width) {
            return index;
        }
    }

    return -1;
}

@_silgen_name("corewlan_set_channel")
public func corewlan_set_channel(intf : String, pos : Int) -> Int
{
	let cwintf = native_interfaces[intf]!
	let cwchannel = channels[intf]![pos]
	let r = try?(cwintf.setWLANChannel(cwchannel))

    if (r == nil) {
        return -1;
    }

    return 1;
}


