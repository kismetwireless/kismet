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
#include "apple80211.h"
#include <Carbon/Carbon.h>
#include "darwin_control_wrapper.h"

@interface DarwinWifi: NSObject {
	id iface;
	NSAutoreleasePool *pool;
	NSBundle *bundle;
	Class CWI_class;
	NSString *ifname;
	WirelessContextPtr *ctx;
}

-(DarwinWifi *) initWithInterface: (NSString *) n;
-(BOOL) getSupportMonitor;
-(void) setIfname: (NSString *) n;
-(void) setPool;
-(void) setBundle;
-(NSArray *) getSupportedChannels;
-(BOOL) setChannel: (unsigned int) c error: (char *) e;
-(BOOL) getCoreWireless;
-(void) disAssociate;

@end;

