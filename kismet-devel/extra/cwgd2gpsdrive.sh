#!/bin/sh

# This doesn't work right

if test "$1" = ""; then
	echo "No cwgd files given."
	exit 1
fi

while test "$1" != ""; do
	if test ! -f $1 -a "$1" != "-"; then
		echo "Couldn't open $1, skipping."
		shift
		continue
	fi

	echo "1001.000000 1001.000000       1001 `date`"
	cat $1 | grep "__TRACK__" | awk -F'\t' '{ printf("%10.6f %10.6f %10.0f %s\n", $3, $4, $5, $11); }'

	shift
done
