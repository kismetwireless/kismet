/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
      but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef __PHYHANDLER_H__
#define __PHYHANDLER_H__

#include "config.h"

#include <stdio.h>

#include "globalregistry.h"
#include "devicetracker.h"

class Devicetracker;

class kis_tracked_device_base;

/*
   Handler element for a phy
   Registered with Devicetracker
   Devicetracker feeds packets to phyhandlers, no need to register with packet 
     chain on each
   Registered phy id is passed from devicetracker

 	Subclasses are expected to:
 	  Register packet handlers in the packet chain
 	  Register packet components in the packet chain
 	  Decode trackable data from a packetsource
 	  Generate trackable devices in the devicetracker
 	  Update tracked device common data via the devicetracker
 	  Provide appropriate network sentences to export non-common tracking data
 	   for the phy type (ie advertised SSID, etc)
 	  Provide per-phy filtering (if reasonable)
 	  Provide per-phy commands (as applicable)
 	  Logging in plaintext and xml
*/

class Kis_Phy_Handler {
public:
	Kis_Phy_Handler() { fprintf(stderr, "fatal oops: kis_phy_handler();\n"); exit(1); }

	// Create a 'weak' handler which provides enough structure to call CreatePhyHandler
	Kis_Phy_Handler(GlobalRegistry *in_globalreg) {
		globalreg = in_globalreg;
		devicetracker = NULL;
		phyid = -1;
		phyname = "NONE";
	}

	virtual Kis_Phy_Handler *CreatePhyHandler(GlobalRegistry *in_globalreg,
											  Devicetracker *in_tracker,
											  int in_phyid) = 0;

	Kis_Phy_Handler(GlobalRegistry *in_globalreg, Devicetracker *in_tracker,
					int in_phyid) {
		globalreg = in_globalreg;
		phyid = in_phyid;
		devicetracker = in_tracker;
	}

	virtual ~Kis_Phy_Handler() {
		// none
	}

	virtual string FetchPhyName() { return phyname; }
	virtual int FetchPhyId() { return phyid; }

	// XSD locations - override as necessary if you provide your xsd, which 
	// you really should
	virtual string FetchPhyXsdNs() { return phyname; }
	virtual string FetchPhyXsdUrl() { 
		return string("http://www.kismetwireless.net/xml/" + FetchPhyXsdNs() + ".xsd"); 
	}

	// Export a device to a central devicetracker-common log file
	//
	// This is used only by the devicetracker registered components to make
	// a unified log file of all devices seen.  This is meant to replace 
	// individual foophy.txt log files, not to supplant a custom dumpfile
	// format.  Plugins / Phy's may still define custom dumpfiles, and should
	// continue to do so, for records which make no sense in the common log.
	//
	// This can not fail - if a phy can't figure out how to log something,
	// it should just bail.
	//
	// The common logger will have already exported the common device statistics
	// such as gps, signal, etc - everything found in the device_common record -
	// and as such a phy logger should export only the data which is not in
	// the common domain.
	//
	// Log type will be the class of log file being written, typically 'xml' 
	// or 'text' but with the option for others in the future.
	//
	// logfile is a standard FILE stream; the location and future handling of it
	// should be considered opaque.  In the case of large written-once files like
	// kisxml the renaming and moving will be handled entirely by the dumpfile
	// class associated.  The logger should only fwrite/fprintf/whatever in
	// whatever format is considered appropriate for the logtype.
	//
	// lineindent is the number of spaces assumed to be used in the display offset
	// already.  For formats such as xml this is irrelevant, but for text output
	// this is the level of indentation which should be done for a consistent look.
	virtual void ExportLogRecord(kis_tracked_device_base *in_device, string in_logtype, 
								 FILE *in_logfile, int in_lineindent) = 0;


protected:
	GlobalRegistry *globalreg;
	Devicetracker *devicetracker;

	string phyname;
	int phyid;
};

#endif

