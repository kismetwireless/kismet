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


/* Global copies */
var channels = [String : [Int]]();
var channels_width = [String : [Int]]();

var interfaces = [String]();

/* Enumerate the corewlan items and put them in our local variables */
@_silgen_name("corewlan_init")
public func corewlan_init() -> Int
{
    interfaces.append("en1demo");
    interfaces.append("en3demo");

    var chans = [Int]();

    chans.append(1);
    chans.append(2);
    chans.append(3);
    chans.append(4);
    chans.append(5);

    channels["en1demo"] = chans;

    var wids = [Int]();

    wids.append(0);
    wids.append(0);
    wids.append(0);
    wids.append(0);
    wids.append(0);

    channels_width["en3demo"] = wids;

    return 1;
}

/* How many interfaces do we have? */
@_silgen_name("corewlan_num_interfaces")
public func corewlan_num_interfaces() -> Int
{
    return interfaces.count;
}

/* Get a single interface */
@_silgen_name("corewlan_get_interface")
public func corewlan_get_interface(pos : Int) -> String
{
    return interfaces[pos];
}

/* Get number of channels */
@_silgen_name("corewlan_num_channels")
public func corewlan_get_num_channels(intf : String) -> Int
{
    return channels[intf]!.count;
}

@_silgen_name("corewlan_get_channel")
public func corewlan_get_channel(intf : String, pos : Int) -> Int
{
    return channels[intf]![pos];
}

@_silgen_name("corewlan_get_channel_width")
public func corewlan_get_channel_width(intf : String, pos : Int) -> Int
{
    return channels_width[intf]![pos];
}

@_silgen_name("corewlan_set_channel")
public func corewlan_set_channel(intf : String, channel : Int, width : Int) -> Int
{
    return 1;
}

