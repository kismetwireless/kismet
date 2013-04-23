#!/usr/bin/env ruby

# Moderately complex example of using Rub with Kismet, compares the relative 
# performance of multiple wifi cards on a Kismet server

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
require 'optparse'

host = "localhost"
port = 2501
$cards = []
$channel = 6

$start_time = 0

# Have not locked cards to a channel yet
$channel_locked = 0
# Have not found all the cards we wanted, yet
$cards_found = 0
# Found cards with UUIDs
$uuid_cards = {}

# card records by uuid
# contains { printed = 0/1, packets = #, last_packets = #, orig_packets = # }
$card_records = {}

# #of lines we've printed
$lines_per_header = 10
$num_printed = 10

# output type (std, pretty, csv)
$output_type = "std"

def sourcecb(proto, fields)
	if fields["error"] != "0"
		puts "ERROR: Source #{fields['interface']} went into error state"
		$k.kill
	end

	if $cards_found == 0
		if $cards.include?(fields["interface"])
			$uuid_cards[fields["interface"]] = fields["uuid"]
			puts "INFO: Found card UUID #{fields['uuid']} for #{fields['interface']}"
		end
	end

	if $channel_locked > 0
		# Add one per source
		# Once we've seen all the sources we expect to see twice, we start outputting
		# tracking data
		if $channel_locked > $cards.length * 2
			if $start_time == 0
				$start_time = Time.now.to_i
				puts "INFO: Started at " + Time.now.inspect
			end

			if $card_records.include?(fields["uuid"]) and $cards.include?(fields["interface"])
				# If we've seen this before, start the scan and print cycle
				r = $card_records[fields["uuid"]]

				r["printed"] = 0
				r["last_packets"] = r["packets"]
				r["packets"] = fields["packets"].to_i - r["orig_packets"]

				$card_records[fields["uuid"]] = r

				all_updated = 1
				$card_records.each { |cr|
					if cr[1]["printed"] == 1 or cr[1]["last_packets"] == 0
						all_updated = 0
						break
					end
				}

				if all_updated == 1
					str = ""
					total = 0
					lasttotal = 0
					best = 0

					if $num_printed == $lines_per_header 
						puts
						hstr = ""

						if $output_type == "pretty"
							hstr = sprintf("%s  %6.6s %5.5s %8.8s %4.4s", hstr, "", "PPS", "Packets", "Pcnt")

						else
							$cards.each { |c|
								hstr = sprintf("%s  %6.6s %5.5s %8.8s %4.4s", hstr, c, "PPS", "Total", "Pcnt")
							}
						end

						hstr = sprintf("%s %6.6s %6.6s", hstr, "Total", "Elpsd")

						puts hstr

						# Stupid kluge for pretty output
						if $output_type == "pretty"
							$cards.each { puts }
							puts
						end


						# Only reset for std, meaning don't print headers for pretty
						if $output_type == "std"
							$num_printed = 0
						end
					end


					$card_records.each { |cr|
						total = total + cr[1]["packets"]
						lasttotal = lasttotal + cr[1]["last_packets"]
						best = cr[1]["packets"] if cr[1]["packets"] > best
					}

					if $output_type == "pretty"
						# Go back up N cards
						print "\x1b[1F\x1b[2K" * ($card_records.length + 1)

						$card_records.each { |cr|
							cr[1]["printed"] = 1

							printf("  %6.6s %5.5s %8.8s %3d%%\n", cr[1]["interface"], cr[1]["packets"] - cr[1]["last_packets"], cr[1]["packets"], (cr[1]["packets"].to_f / best.to_f) * 100)
						}

						t = Time.now.to_i - $start_time
						tu = ""

						if t > 60*60
							th = t/60/60
							tu = "#{th}h"
							t = t - (th * 3600)
						end
						
						if t > 60
							tm = t / 60
							tu += "#{tm}m"
							t = t - (tm * 60)
						end
					
						if t
							tu += "#{t}s"
						end

						printf("  %6.6s %5.5s %8.8s %4.4s %6.6s %6.6s\n", "", "", "", "", total - lasttotal, tu)
					else
						$card_records.each { |cr|
							cr[1]["printed"] = 1

							cname = ""
							cname = cr[1]["interface"] if $output_type == "pretty"

							str = sprintf("%s  %6.6s %5.5s %8.8s %3d%%", str, cname, cr[1]["packets"] - cr[1]["last_packets"], cr[1]["packets"], (cr[1]["packets"].to_f / best.to_f) * 100)
						}

						t = Time.now.to_i - $start_time
						tu = ""

						if t > 60*60
							th = t/60/60
							tu = "#{th}h"
							t = t - (th * 3600)
						end
						
						if t > 60
							tm = t / 60
							tu += "#{tm}m"
							t = t - (tm * 60)
						end
					
						if t
							tu += "#{t}s"
						end

						str = sprintf("%s %6.6s %6.6s", str, total - lasttotal, tu)

						puts str
					end

					$num_printed = $num_printed + 1

				end

			elsif $cards.include?(fields["interface"])
				r = {}
				r["interface"] = fields["interface"]
				r["printed"] = 0
				r["last_packets"] = 0
				r["orig_packets"] = fields["packets"].to_i
				r["packets"] = fields["packets"].to_i - r["orig_packets"]

				$card_records[fields["uuid"]] = r
			end
		else
			$channel_locked = $channel_locked + 1
		end
	end
end

def lockcback(text)
	if text != "OK"
		puts "ERROR: Failed to lock source to channel: #{text}"
		$k.kill
		exit
	end
end

def sourcecback(text)
	if $uuid_cards.length != $cards.length
		puts "ERROR:  Couldn't find specified cards:"
		$cards.each { |c|
			puts "\t#{c}" if not $uuid_cards.include?(c)
		}

		$k.kill
	else
		$cards_found = 1

		puts "INFO: Locking #{$cards.join(", ")} to channel #{$channel}"

		$uuid_cards.each { |c|
			$k.command("HOPSOURCE #{c[1]} LOCK #{$channel}", Proc.new {|*args| lockcback(*args)})
		}

		$channel_locked = 1

		puts("INFO: Waiting for sources to settle on channel...")

	end
end

# No sources specified, print out the list of sources Kismet knows about
def nosourcecb(proto, fields)
	errstr = ""
	if fields['error'] != "0"
		errstr = "[IN ERROR STATE]"
	end
	puts "\t#{fields['interface']}\t#{fields['type']}\t#{errstr}"
end

# As soon as we get the ack for this command, kill the connection, because
# we're in no-sources-specified mode
def nosourceack(text)
	$k.kill
end

options = {}

OptionParser.new do |opts|
	opts.banner = "Usage: shootout.rb [options] source1 ... sourceN"

	opts.on("--host HOST", "Connect to server on host") do |h|
		options[:host] = h
	end

	opts.on("--port PORT", "Connect to server on PORT") do |p|
		options[:port] = p
	end

	opts.on("--channel CHANNEL", "Test on CHANNEL (default 6)") do |c|
		options[:channel] = c
	end

	opts.on("--pretty", "Format output with pretty ANSI codes") do 
		options[:pretty] = true
	end

end.parse!

if options[:host]
	host = options[:host]
end

if options[:port]
	if options[:port].match(/[^0-9]+/) != nil
		puts "ERROR:  Invalid port, expected number"
		exit
	end

	port = options[:port].to_i
end

if options[:channel]
	if options[:channel].match(/[^0-9]+/) != nil
		puts "ERROR:  Invalid channel, expected number"
		exit
	end

	$channel = options[:channel].to_i
end


if options[:pretty]
	$output_type = "pretty"
end

$cards = ARGV

puts "INFO: Kismet NIC Shootout"
puts "      Compare capture performance of multiple NICs"
puts

puts "INFO: Connecting to Kismet server on #{host}:#{port}"

$k = Kismet.new(host, port)

begin
	$k.connect()
rescue Errno::ECONNREFUSED
	puts "ERROR:  Kismet server not running (connection refused)"
	puts "ERROR:  Will retry connecting in 5 seconds"
	sleep(5)
	retry
end

$k.run()

if $cards.length == 0
	puts "ERROR:  No capture sources specified.  Available capture sources:"

	$k.subscribe("source", ["interface", "type", "username", "error"], Proc.new {|*args| nosourcecb(*args)}, Proc.new {|*args| nosourceack(*args)})

	$k.wait

	exit
end

puts "INFO: Testing sources #{$cards.join(", ")} on channel #{$channel}"

# Print a header line
$num_printed = $lines_per_header

$k.subscribe("source", ["interface", "type", "username", "channel", "uuid", "packets", "error"], Proc.new {|*args| sourcecb(*args)}, Proc.new {|*args| sourcecback(*args)})

$k.wait


#$k = Kismet.new(host, port)
#
#$k.connect()
#
#$k.run()
#
#$k.subscribe("bssid", ["bssid", "type", "channel", "firsttime", "lasttime"], Proc.new {|*args| bssidcb(*args)})
#
#$k.wait()
