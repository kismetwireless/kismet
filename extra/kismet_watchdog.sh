#!/bin/sh
# kismet_watchdog - keep Kismet alive

NAME=kismet_server
PIDFILE=/var/run/$NAME.pid
MYNAME=kismet_watchdog
MYPIDFILE=/var/run/$MYNAME.pid

test -x $DAEMON || exit 0

# Function to get the PID of Kismet
getpid()
{
	if [ -s $PIDFILE ]
	then
		PID=`cat $PIDFILE`
	else
		PID=0
	fi
}

# Save our PID, so that other can find us...
echo $$ > $MYPIDFILE

# Renice ourself and our child. This means that we, and Kismet, will
# run at lower priority.
renice >/dev/null 15 $$

# Limit the amount of memory we can use. This will prevent Kismet
# From using all the memory and system going down.
# 5500kB seems about right to leave about 512K free on the system
ulimit -v 5500

# Initialise the 'dead' counter to some high value to immediately
# launch Kismet
DEAD_CNT=2

# Infinite loop
while true; do
        DEAD_CNT=`expr $DEAD_CNT + 1`

	# Check if there is a PID file
	getpid
	if [ $PID != 0 ]
	then
		# Check if the program is running
		if [ -d /proc/$PID ]
		then
			# Alive : i.e. not dead
			DEAD_CNT=0
		else
			echo "Kismet_Watchdog : Kismet not running."
		fi
	else
		echo "Kismet_Watchdog : no PID file."
	fi

	# Check if we reach our limit. We don't restart kismet everytime
	# we don't see it because Kismet takes time to start
	if [ $DEAD_CNT -gt 1 ]
	then
		echo "Kismet_Watchdog : Kismet is dead, restarting..."

		# Stop all potential kismet instances
		killall kismet_server

		# Let's clean up the old log files to save memory space.
		# We zero them, but don't get rid of them. We want
		# a new file name each time kismet restart.
		KFILELIST=/tmp/Kismet-*.csv
		for KFILE in $KFILELIST ; do
			# The patern above expand to itself if no file
			# exist, and not an empty string. This catches this
			# And prevent creating a file with a '*' in it.
			if [ -e "$KFILE" ]
			then
				cat /dev/null > "$KFILE"
			fi
		done

		# Restart Kismet
		/usr/bin/kismet_server 2> /dev/null &

		# Make sure we wait a bit */
		DEAD_CNT=0
	fi

	# sleep a while to not overwhelm the system
	sleep 5

# end infinite loop
done
