# CSV2MySQL support 
# Updated: Mike Kerhaw
# Date:   2002/07/09
# Author: Reyk Floeter <reyk@synack.de>
# Date:   2002/03/13
#
# create a table to import kismet CSV logs... (MySQL- style)

CREATE TABLE kismet       (Network int, 
              NetType char(15),
              ESSID varchar(255), 
              BSSID char(17) DEFAULT '00:00:00:00:00:00', 
              Info varchar(255),
              Channel int,
              Maxrate float,
              WEP enum('Yes', 'No') DEFAULT 'No',
              LLC int, 
              Data int, 
              Crypt int, 
              Weak int, 
              Total int,
              First varchar(255),
              Last varchar(255),
              GPSMinLat float,
              GPSMinLon float,
              GPSMinAlt float, 
              GPSMinSpd float,
              GPSMaxLat float, 
              GPSMaxLon float, 
              GPSMaxAlt float, 
              GPSMaxSpd float, 
              DHCP varchar(15), 
              DHCPNetmask varchar(15), 
              DHCPGateway varchar(15), 
              ARP varchar(15), 
              UDP varchar(15),
              TCP varchar(15),
              id int PRIMARY KEY auto_increment
);

