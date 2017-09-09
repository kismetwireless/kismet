#!/usr/bin/env ruby

# Basic example of logging Kismet alerts to Syslog with the Ruby client code

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
require 'pp'
require "getopt/long"
require 'syslog'

include Getopt

def alertcb(proto, fields)
	# *CAPABILITY: ALERT sec,usec,header,bssid,source,dest,other,channel,text,phytype
	puts("#{fields['header']} bssid=#{fields['bssid']} server-ts=#{fields['sec']} source=#{fields['source']} dest=#{fields['dest']} channel=#{fields['channel']} #{fields['text']}");
	Syslog.log(Syslog::LOG_CRIT, "#{fields['header']} server-ts=#{fields['sec']} bssid=#{fields['bssid']} source=#{fields['source']} dest=#{fields['dest']} channel=#{fields['channel']} #{fields['text']}");
end

host = "localhost"
port = 2501
logid = "kismet"

opt = Long.getopts(
	["--host", "", REQUIRED],
	["--port", "", REQUIRED],
	["--logid", "", REQUIRED]
	)

if opt["host"]
	host = opt["host"]
end

if opt["port"]
	if opt["port"].match(/[^0-9]+/) != nil
		puts "ERROR:  Invalid port, expected number"
		exit
	end

	port = opt["port"].to_i
end

if opt["logid"]
	logid = opt["logid"]
end

puts "INFO: Connecting to Kismet server on #{host}:#{port}"
puts "INFO: Logging to syslog, id #{logid}"

Syslog.open(logid, Syslog::LOG_NDELAY, Syslog::LOG_USER)

$k = Kismet.new(host, port)

$k.connect()

$k.run()

$k.subscribe("alert", ["header", "sec", "bssid", "source", "dest", "channel", "text"], Proc.new {|*args| alertcb(*args)})

$k.wait()
