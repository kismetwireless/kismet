#!/bin/sh
# make a lot of small maps out of a kismet track

# this should be the only user-settable parameter
scale=1800

awk '/gps-point/ { if ( $3 ~ "source.*" ) { print $6" "$7 } else { print $5" "$6 }}' < $1 | while read line; do
	eval $line
	if [[ $lat != 0 ]]; then
		echo $lat
		cat > /dev/null
		break
	fi
done > /tmp/mg$$

latitude=`cat /tmp/mg$$`

bc -l << EOF > /tmp/mg$$
scale=3
c(($latitude * 8 * a(1))/360)
EOF

cos_lat=`cat /tmp/mg$$`
rm /tmp/mg$$

awk '/gps-point/ { if ( $3 ~ "source.*" ) { print $6" "$7 } else { print $5" "$6 }}' < $1 | while read line; do
	eval $line
	echo $lat $lon 
done | awk -v cos_lat=$cos_lat -v scale=$scale 'BEGIN {olat=0}
	    { if ( olat == 0 ) {
			count = 1
			trig_dist = scale / 80000000
			print "gpsmap -tG -l name,bssid,manuf -c "$1","$2" -s "scale" -o map"count".gif"
			olat = $1
			olon = $2
			maxdist = 0
			count = count + 1
		} else if ( $1 != 0 ) {
			latdiff = ( $1 - olat ) * cos_lat
			londiff = $2 - olon
			dist = latdiff * latdiff + londiff * londiff
			if ( dist > maxdist ) {
				maxdist = dist
			}
			if ( dist > trig_dist || ( maxdist - dist ) > ( trig_dist / 10) ) {
				print "gpsmap -tG -l name,bssid,manuf -c "$1","$2" -s "scale" -o map"count".gif"
				olat = $1
				olon = $2
				maxdist = 0
				count = count + 1
			}
			lastlat = $1
			lastlon = $2
		}
	}
	END {
		print "gpsmap -tG -l name,bssid,manuf -c "lastlat","lastlon" -s "scale" -o map"count".gif"
	}' | while read line; do
		echo $line $1
		eval $line $1
done
