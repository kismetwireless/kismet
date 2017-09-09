#!/bin/sh

# translate data from <http://standards.ieee.org/regauth/oui/oui.txt>
# to kismet format

sed -n 's,^\(..\)-\(..\)-\(..\)[ 	]*(hex)[ 	]*\(.*\)$,\1:\2:\3:00:00:00/FF:FF:FF:00:00:00	\4	Unknown	0,p'
