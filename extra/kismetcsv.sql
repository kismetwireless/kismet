# CSV2MySQL support 
# Updated: Mike Kershaw
# Date:   2003/07/24
# Updated: Mike Kerhaw
# Date:   2002/07/09
# Author: Reyk Floeter <reyk@synack.de>
# Date:   2002/03/13
#
# create a table to import kismet CSV logs... (MySQL- style)

CREATE TABLE kismet       (
		Network integer, 
        NetType char(15),
        ESSID varchar(255), 
        BSSID char(17) DEFAULT '00:00:00:00:00:00', 
        Info varchar(255),
        Channel integer,
		Cloaked enum("Yes", "No"),
		WEP enum("Yes", "No"),
		Decrypted enum("Yes", "No"),
		Maxrate float,
		MaxSeenRate float,
		Beacon integer,
        LLC integer, 
        Data integer, 
        Crypt integer, 
        Weak integer, 
        Total integer,
		Carrier varchar(255),
		Encoding varchar(255),
        First varchar(255),
        Last varchar(255),
        BestQuality integer,
        BestSignal integer,
        BestNoise integer,
        GPSMinLat float,
        GPSMinLon float,
        GPSMinAlt float, 
        GPSMinSpd float,
        GPSMaxLat float, 
        GPSMaxLon float, 
        GPSMaxAlt float, 
        GPSMaxSpd float, 
		GPSBestLat float,
		GPSBestLon float,
		GPSBestAlt float,
		Datasize long integer,
		IPType varchar(25),
		IP varchar(15),
        id int PRIMARY KEY auto_increment
);

