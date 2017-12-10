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
var channels = [CWChannel]();
var native_interface = CWInterface();
var interfaces = [String]();

/* Enumerate the corewlan items and put them in our local variables */
@_silgen_name("corewlan_init")
public func corewlan_init(in_ifname : UnsafePointer<UInt8>) -> Int
{
    let ifname = String(cString: in_ifname)

print(ifname)
    /* There is almost certainly a smarter way to do this, but we are
       not swift programmers.  Patches definitely welcome. */
    if #available(OSX 10.10, *) {
        let wf = CWWiFiClient()
        let interfs = [wf!.interfaces()]
        let interfenum = interfs.enumerated()

        for (_, intfs) in interfenum {
            for intf in intfs! {
                let intname = intf.interfaceName!
                if (intname == ifname) {
                    native_interface = intf;
                    let chans = [intf.supportedWLANChannels()]
                    let enumchans = chans.enumerated()

                    for (_, chanblob) in enumchans{
                        for channel in chanblob! {
                            channels.append(channel)
                        }
                    }
                }
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
    if #available(OSX 10.10, *) {
        let wf = CWWiFiClient()
        let interfs = [wf!.interfaces()]
        let interfenum = interfs.enumerated()

        for (_, intfs) in interfenum {
            for intf in intfs! {
                let intname = intf.interfaceName!
                interfaces.append(intname);
            }
        }
        return interfaces.count;
    } else {
        return -1;
    }
}

/* Get a single interface */
@_silgen_name("corewlan_get_interface")
public func corewlan_get_interface(pos : Int) -> UnsafePointer<Int8>
{
    return UnsafePointer<Int8>(strdup(interfaces[pos]));
}

/* Get number of channels */
@_silgen_name("corewlan_num_channels")
public func corewlan_num_channels() -> Int
{
    return channels.count;
}

@_silgen_name("corewlan_get_channel")
public func corewlan_get_channel(pos : Int) -> Int
{
    return channels[pos].channelNumber;
}

@_silgen_name("corewlan_get_channel_width")
public func corewlan_get_channel_width(pos : Int) -> Int
{
    return channels[pos].channelWidth.rawValue;
}

@_silgen_name("corewlan_find_channel")
public func corewlan_find_channel(channel : Int, width : Int) -> Int
{
    for (index, c) in channels.enumerated() {
        if (c.channelNumber == channel && c.channelWidth.rawValue == width) {
            return index;
        }
    }

    return -1;
}

@_silgen_name("corewlan_set_channel")
public func corewlan_set_channel(pos : Int) -> Int
{
	let cwchannel = channels[pos]
	let r = try?(native_interface.setWLANChannel(cwchannel))

    if (r == nil) {
        return -1;
    }

    return 1;
}


