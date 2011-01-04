#!/usr/bin/env ruby

# Very basic example for logging Kismet data to SQLite
# Would need to be expanded for more fields and better logging,
# contributions happily accepted

require 'socket'
require 'time'
require 'kismet'
require 'pp'
require "getopt/long"
require "sqlite3"

include Getopt

def Mac2Int(mac)
	#puts "#{mac[0,2]} #{mac[3,2]} #{mac[6,2]} #{mac[9,2]} #{mac[12,2]} #{mac[15,2]}"
	i = 0

	i = i + (mac[0,2].to_i(16) << (5 * 8))
	i = i + (mac[3,2].to_i(16) << (4 * 8))
	i = i + (mac[6,2].to_i(16) << (3 * 8))
	i = i + (mac[9,2].to_i(16) << (2 * 8))
	i = i + (mac[12,2].to_i(16) << (1 * 8))
	i = i + mac[15,2].to_i(16)

	return i
end

def Int2Mac(macint)
	m = ""

	m = m + ((macint >> (5 * 8)) & 0xFF).to_s(16) + ":"
	m = m + ((macint >> (4 * 8)) & 0xFF).to_s(16) + ":"
	m = m + ((macint >> (3 * 8)) & 0xFF).to_s(16) + ":"
	m = m + ((macint >> (2 * 8)) & 0xFF).to_s(16) + ":"
	m = m + ((macint >> (1 * 8)) & 0xFF).to_s(16) + ":"
	m = m + ((macint) & 0xFF).to_s(16)

	return m
end

def bssidcb(proto, fields)
	$db.execute("BEGIN TRANSACTION")

	mi = Mac2Int(fields['bssid'])

	r = $db.execute("SELECT bssid FROM bssid WHERE bssid=#{mi}")

	if (r.length == 0)
		puts "INFO: new network #{fields["bssid"]}"

		$db.execute("INSERT INTO bssid (bssid, type, channel, firsttime, lasttime) VALUES (#{mi}, #{fields['type']}, #{fields['channel']}, #{fields['firsttime']}, #{fields['lasttime']})")
	else
		puts "INFO: updating network #{fields["bssid"]}"
		
		$db.execute("UPDATE bssid SET type=#{fields['type']}, channel=#{fields['channel']}, lasttime=#{fields['lasttime']} WHERE bssid=#{mi}")
	end

	$db.execute("COMMIT")
end

host = "localhost"
port = 2501
sqlfile = "kismet.sql3"

opt = Long.getopts(
	["--host", "", REQUIRED],
	["--port", "", REQUIRED],
	["--database", "", REQUIRED]
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

if opt["database"]
	sqlfile = opt["database"]
end

puts "INFO: Connecting to Kismet server on #{host}:#{port}"
puts "INFO: Logging to database file #{sqlfile}"

if not File::exists?(sqlfile)
	$db = SQLite3::Database.new(sqlfile)

	$db.execute("BEGIN TRANSACTION")
	$db.execute("CREATE TABLE bssid ( bssid INTEGER PRIMARY KEY, type INTEGER, channel INTEGER, firsttime INTEGER, lasttime INTEGER )")
	$db.execute("COMMIT")
else
	$db = SQLite3::Database.new(sqlfile)
end

$k = Kismet.new(host, port)

$k.connect()

$k.run()

$k.subscribe("bssid", ["bssid", "type", "channel", "firsttime", "lasttime"], Proc.new {|*args| bssidcb(*args)})

$k.wait()
