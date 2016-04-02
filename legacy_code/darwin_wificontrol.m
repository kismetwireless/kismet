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


#define __IN_OBJC_FILE__

#import <Foundation/Foundation.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#import "darwin_wificontrol.h"

/* From Macstumber rev-eng darwin headers */
WIErr wlc_ioctl(WirelessContextPtr ctx, int command, int bufsize,
                                void *buffer, int outsize,  void *out) {
        if (!buffer)
                bufsize = 0;

        int *buf = (int *) malloc(bufsize+8);

        buf[0] = 3;
        buf[1] = command;

        if (bufsize && buffer) {
                memcpy(&buf[2], buffer, bufsize);
        }

        return WirelessPrivate(ctx, buf, bufsize+8, out, outsize);
}


@implementation DarwinWifi

-(DarwinWifi *) initWithInterface: (NSString *) n {
	self = [super init];

	if (self) {
		[self setIfname:n];
		[self setPool];
		[self setBundle];
	}

	return self;
}

-(void) setIfname: (NSString *) n {
	iface = n;
}

-(void) setPool {
	pool = [[NSAutoreleasePool alloc] init];
}

-(BOOL) getSupportMonitor {
	return [iface supportsMonitorMode];
}

-(BOOL) getCoreWireless {
	return (iface != nil);
}

-(void) setBundle {
	bundle = [[NSBundle alloc] initWithPath:@"/System/Library/Frameworks/CoreWLAN.framework"];
	CWI_class = [bundle classNamed:@"CWInterface"];

	if (CWI_class != nil) {
		iface = [CWI_class interfaceWithName:ifname];
		ctx = nil;
	} else {
		iface = nil;
		WirelessAttach(&ctx, 0);
	}
}

-(NSArray *) getSupportedChannels {
	NSArray *ret = nil;

	// We only know how to return the channels on corewireless
	if (iface != nil) {
		ret = [iface supportedChannels];
	}

	return ret;
}

-(void) disAssociate {
	if (iface != nil) {
		[iface disassociate];
	} else if (ctx != nil) {
		// Disassociate
    		wlc_ioctl(ctx, 52, 0, NULL, 0, NULL);
	}
}

-(BOOL) setChannel: (unsigned int) c error: (char *) e {
	NSError *wcerr;
	BOOL ret;

	if (iface != nil) {
		[iface disassociate];

		ret = [iface setChannel:c error:&wcerr];

		if (!ret) {
			snprintf(e, 1024, "%s", [[wcerr localizedDescription] cString]);
		}
	
		return ret;
	} else if (ctx != nil) {
		// Disassociate
    		wlc_ioctl(ctx, 52, 0, NULL, 0, NULL);
		// Set channel
    		wlc_ioctl(ctx, 30, 8, &c, 0, NULL);

		return 1;
	} 

	snprintf(e, 1024, "Missing CoreWireless -and- older Darwin config info");

	return 0;
}

@end;	
