#!/usr/bin/env ruby

# Very basic demo using the Kismet Ruby code to extract a list of networks

#   This file is part of Kismet
#
#   Kismet is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   Kismet is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with Kismet; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

require 'socket'
require 'time'
require_relative 'kismet'

def bssidcb(proto, fields)
	puts "Kismet saw network #{fields['bssid']} manuf #{fields['manuf']} on channel #{fields['channel']}"
end

def bssiddiecb(text)
	puts "BSSID ack"
	$k.kill
	exit
end

$k = Kismet.new()

$k.connect()

$k.run()

$k.subscribe("bssid", ["bssid", "manuf", "channel"], Proc.new {|*args| bssidcb(*args)}, Proc.new {|*args| bssiddiecb(*args)})

$k.wait()
