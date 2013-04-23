#!/usr/bin/env ruby

# Kismet protocol Ruby interface

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
require 'pp'

class Kismet
	def initialize(host = "localhost", port = 2501)
		@port = port
		@host = host
		@die = 0
		@cmd = 0
		@callbacks = { }
		@ackbacks = { }
		@thr = nil
	end

	def connect()
		@die = 0
		@conn = TCPSocket.new(@host, @port)
	end

	def run()
		@thr = Thread.new() {
			while 1
				begin
					#print @conn.gets() + "\n"
					parseline @conn.gets()
				rescue Exception => e
					pp e

					raise e

					break
				end
			end
		}
	end

	def sendraw(txd)
		begin
			@conn.puts(txd)
		rescue Exception => e
			pp e

			puts "write error: #{$!}"
		end
	end

	def kill()
		@die = 1
		@conn.close
		@thr.kill
		@thr.join if not @thr == nil
	end

	def wait()
		@thr.join
	end

	def parseline(line)
		re = Regexp.new(/\*([A-Z0-9]+): (.*)\n/)
		
		md = re.match(line)
		
		exit if md == nil
		
		#puts md.length
		
		#for ss in 1..md.length
		#	puts md[ss]
		#end
		
		return if md.length != 3

		p = md[1].upcase

		if p == "ACK"
			f = parsedata(["cmdid", "text"], md[2])

			id = f['cmdid'].to_i

			if @ackbacks[id] != nil
				@ackbacks[id].call(f['text'])
				@ackbacks[id] = nil
			end
			
			return p
		end

		if @callbacks[p] != nil
			f = parsedata(@callbacks[p][0], md[2])
			#puts "#{p} got #{f.length} fields"
			@callbacks[p][1].call(p, f)
		end

		return md[1]
	end

	def parsedata(fields, data)
		in_delim = 0
		pos = 0

		da = {}
		f = ""
		fnum = 0

		for pos in 0..data.length - 1
			if data[pos, 1] == "\001" and in_delim == 1
				in_delim = 0
				next
			elsif data[pos, 1] == "\001" and in_delim == 0
				in_delim = 1
				next
			elsif data[pos, 1] == ' ' and in_delim == 0
				#puts "#{fields[fnum]} #{f}"
				da[fields[fnum]] = f
				fnum = fnum + 1
				f = ""
				next
			else 
				f << data[pos, 1]
			end

			# printf "%c", data[pos]
		end

		#puts "#{fields[fnum]} #{f}"
		da[fields[fnum]] = f

		return da
	end

	def subscribe(proto, fields, hndl, ackback = nil)
		p = proto.upcase

		# puts "subscribe #{p} #{fields}"

		if @callbacks[p] != nil
			puts "!!! #{p} already declared with fields #{@callbacks[p][0]}, replacing"
		end

		@callbacks[p] = [ fields, hndl ]

		fe = ""

		fields.each { |f| fe << "#{f}," }

		if ackback != nil 
			@ackbacks[@cmd] = ackback
		end

		sendraw("!#{@cmd} ENABLE #{p} #{fe}\n")

		@cmd = @cmd + 1
		
	end

	def unsubscribe(proto)
		p = proto.upcase
		
		@callbacks[p] = nil

		sendraw("!0 REMOVE #{p}")
	end

	def command(command, ackback = nil)
		if ackback != nil 
			@ackbacks[@cmd] = ackback
		end

		sendraw("!#{@cmd} #{command}\n")

		@cmd = @cmd + 1
		
	end

end

def genericcb(proto, fields)
	puts "Proto #{proto} numf #{fields.length}"
end
