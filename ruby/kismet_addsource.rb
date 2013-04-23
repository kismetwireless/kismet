#!/usr/bin/env ruby

# basic tool for adding sources to Kismet runtime

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

$nacks = 0
$nsrc = 0

def addsourcecb(text)
	if text != "OK"
		puts "ERROR:  Failed to add source, #{text}"
	end
	$nacks = $nacks + 1

	if $nacks = $nsrc
		puts "INFO: All sources added"
		$k.kill
	end
end

options = {}
OptionParser.new do |opts|
  opts.banner = "Usage: addsource.rb [options] interface[:sourceopts] ..."

  opts.on("--host HOST", "Connect to server on host") do |h|
  	options[:host] = h
  end

  opts.on("--port PORT", "Connect to server on PORT") do |p|
  	opts[:port] = p
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

puts "INFO: Connecting to Kismet server on #{host}:#{port}"

$nsrc = ARGV.length

$k = Kismet.new(host, port)

$k.connect()

$k.run()

ARGV.each { |s|
	puts "INFO: Adding source #{s}"
	$k.command("ADDSOURCE #{s}", Proc.new {|*args| addsourcecb(*args)})
}

$k.wait

