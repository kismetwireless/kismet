while [ -f /tmp/kismet_remote/$1 ]; do 
	/usr/local/bin/kismet_capture_tools/$1 --connect $2 --source $3
	sleep 5;
done

print "/tmp/kismet_remote/$1 no longer present, stopping loop"
