#!/usr/bin/env ruby

require 'socket'
require 'time'
require 'kismet'

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
