#!/usr/bin/env ruby

# Very basic example for logging Kismet data to SQLite
# Would need to be expanded for more fields and better logging,
# contributions happily accepted

require 'socket'
require 'time'
require 'kismet'
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
