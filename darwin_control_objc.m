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

#include "config.h"

#ifdef SYS_DARWIN

// Is this a bad idea, to try to merge obj-c and c++ code into one codebase?
// Yes, probably.
// Code derived from kismac by KF

#import <Foundation/Foundation.h>
#include <unistd.h>

int darwin_bcom_testmonitor()
{
	NSDictionary *dict;
	NSData *fileData;
	NSAutoreleasePool *pool;
	pool  = [[NSAutoreleasePool alloc] init];

	fileData = [NSData dataWithContentsOfFile:@"/System/Library/Extensions/AppleAirPort2.kext/Contents/Info.plist"];
	dict = [NSPropertyListSerialization propertyListFromData:fileData mutabilityOption:kCFPropertyListImmutable format:NULL errorDescription:Nil];
	if ([[dict valueForKeyPath:@"IOKitPersonalities.Broadcom PCI.APMonitorMode"] boolValue]) return -1;

	fileData = [NSData dataWithContentsOfFile:@"/System/Library/Extensions/IO80211Family.kext/Contents/PlugIns/AppleAirPortBrcm4311.kext/Contents/Info.plist"];
	dict = [NSPropertyListSerialization propertyListFromData:fileData mutabilityOption:kCFPropertyListImmutable format:NULL errorDescription:Nil];
	if ([[dict valueForKeyPath:@"IOKitPersonalities.Broadcom PCI.APMonitorMode"] boolValue]) return -1;

	return 1;
}

int darwin_bcom_enablemonitorfile(const char *c_filename)
{
	NSDictionary *dict;
	NSData *data;
	pid_t pid;
	NSString *fileName;
	NSAutoreleasePool *pool;

	pool  = [[NSAutoreleasePool alloc] init];
	fileName = [[NSString alloc] initWithCString:c_filename]; 

	if( (pid=fork()) == -1) { return -1; }
	if(pid == 0)
	{
		execl("/bin/chmod", "chmod", "666", [fileName cString], NULL );	
	}
	sleep( 1);
	data = [NSData dataWithContentsOfFile:fileName];
	if(!data) return 0;
	dict = [NSPropertyListSerialization propertyListFromData:data mutabilityOption:kCFPropertyListMutableContainers format:NULL errorDescription:Nil];
	if(!dict) return 0;
	[dict setValue:[NSNumber numberWithBool:true] forKeyPath:@"IOKitPersonalities.Broadcom PCI.APMonitorMode"];
	[[NSPropertyListSerialization dataFromPropertyList:dict format:kCFPropertyListXMLFormat_v1_0 errorDescription:nil] writeToFile:fileName atomically:NO];

	if( (pid=fork()) == -1) { return 0; }
	if(pid == 0)
	{
		execl("/bin/chmod", "chmod", "644", [fileName cString], NULL );	
	}
	return 1;	
}

int darwin_bcom_enablemonitor() 
{
	pid_t pid;
	int ret;
	NSAutoreleasePool *pool;
	pool  = [[NSAutoreleasePool alloc] init];

	ret = darwin_bcom_enablemonitorfile("/System/Library/Extensions/AppleAirPort2.kext/Contents/Info.plist") || 
		darwin_bcom_enablemonitorfile("/System/Library/Extensions/IO80211Family.kext/Contents/PlugIns/AppleAirPortBrcm4311.kext/Contents/Info.plist");

	if (ret == 0) {
		return -1;
	}

	if( (pid=fork()) == -1) { return -1; }
	if(pid == 0)
	{
		execl("/bin/rm", "rm", "/System/Library/Extensions.kextcache", NULL);	
	}
	if( (pid=fork()) == -1) { return -1; }
	if(pid == 0)
	{
		execl("/usr/sbin/kextcache", "kextcache", "-k", "/System/Library/Extensions", NULL );	
	}
	if( (pid=fork()) == -1) { return -1; }
	if(pid == 0)
	{
		execl("/bin/rm", "rm", "/System/Library/Extensions.mkext", NULL );	
	}
	if( (pid=fork()) == -1) { return -1; }
	if(pid == 0)
	{
		execl("/sbin/kextunload", "kextunload", "-b", "com.apple.driver.AppleAirPort2", NULL );	
	}
	if( (pid=fork()) == -1) { return -1; }
	if(pid == 0)
	{
		execl("/sbin/kextload", "kextload", "/System/Library/Extensions/AppleAirPort2.kext", NULL );	
	}

	return 1;
}

#endif

