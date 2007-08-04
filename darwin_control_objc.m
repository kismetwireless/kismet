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
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

int darwin_bcom_testmonitor()
{
	NSDictionary *dict;
	NSData *fileData;
	NSAutoreleasePool *pool;
	pool  = [[NSAutoreleasePool alloc] init];

	fileData = [NSData dataWithContentsOfFile:@"/System/Library/Extensions/AppleAirPort2.kext/Contents/Info.plist"];
	dict = [NSPropertyListSerialization propertyListFromData:fileData mutabilityOption:kCFPropertyListImmutable format:NULL errorDescription:Nil];
	if ([[dict valueForKeyPath:@"IOKitPersonalities.Broadcom PCI.APMonitorMode"] boolValue]) return 1;

	fileData = [NSData dataWithContentsOfFile:@"/System/Library/Extensions/IO80211Family.kext/Contents/PlugIns/AppleAirPortBrcm4311.kext/Contents/Info.plist"];
	dict = [NSPropertyListSerialization propertyListFromData:fileData mutabilityOption:kCFPropertyListImmutable format:NULL errorDescription:Nil];
	if ([[dict valueForKeyPath:@"IOKitPersonalities.Broadcom PCI.APMonitorMode"] boolValue]) return 1;

	return -1;
}

int darwin_bcom_enablemonitorfile(const char *c_filename)
{
	NSDictionary *dict;
	NSData *data;
	NSString *fileName;
	NSAutoreleasePool *pool;

	pool  = [[NSAutoreleasePool alloc] init];
	fileName = [[NSString alloc] initWithCString:c_filename]; 
	
	if (chmod([fileName cString],
		(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) < 0 &&
		errno != ENOENT) {
		return -1;
	}	

	data = [NSData dataWithContentsOfFile:fileName];
	if(!data) return 0;
	dict = [NSPropertyListSerialization propertyListFromData:data mutabilityOption:kCFPropertyListMutableContainers format:NULL errorDescription:Nil];
	if(!dict) return 0;
	[dict setValue:[NSNumber numberWithBool:true] forKeyPath:@"IOKitPersonalities.Broadcom PCI.APMonitorMode"];
	[[NSPropertyListSerialization dataFromPropertyList:dict format:kCFPropertyListXMLFormat_v1_0 errorDescription:nil] writeToFile:fileName atomically:NO];

	if (chmod([fileName cString],
		(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0 && errno != ENOENT) {
		return -1;
	}	

	return 1;	
}

int darwin_bcom_enablemonitor() 
{
	int ret;
	NSAutoreleasePool *pool;
	pool  = [[NSAutoreleasePool alloc] init];
	char cmd[1024];

	ret = darwin_bcom_enablemonitorfile("/System/Library/Extensions/AppleAirPort2.kext/Contents/Info.plist") || 
		darwin_bcom_enablemonitorfile("/System/Library/Extensions/IO80211Family.kext/Contents/PlugIns/AppleAirPortBrcm4311.kext/Contents/Info.plist");

	if (ret == 0) {
		return -1;
	}

	if (unlink("/System/Library/Extensions.kextcache") < 0 && errno != ENOENT)
		return -1;

	snprintf(cmd, 1024, "/usr/sbin/kextcache -k /System/Library/Extensions");
	if (system(cmd) != 0)
		return -1;

	if (unlink("/System/Library/Extensions.mkext") < 0 && errno != ENOENT)
		return -1;

	/* Throw a warning at the user and wait */
	fprintf(stderr, "ATTENTION:  Kismet has enabled rfmon on your devices, however to "
			"activate it, the kernel modules must be reloaded.  There have been reports "
			"of this causing a system crash.  Kismet will wait 10 seconds before "
			"attempting to reload the kernel modules.  Press control-c now to cancel "
			"reloading modules and reboot manually if you do not want to proceed!\n\n");

	sleep(10);

	/* we don't check the failure codes since we don't know which driver we're using */
	snprintf(cmd, 1024, "/sbin/kextunload -b com.apple.driver.AppleAirPort2"
			 ">/dev/null 2>/dev/null");
	system(cmd);

	snprintf(cmd, 1024, "/sbin/kextload /System/Library/Extensions/AppleAirPort2.kext"
			 ">/dev/null 2>/dev/null");
	system(cmd);

	snprintf(cmd, 1024, "/sbin/kextunload -b com.apple.driver.AppleAirPortBrcm4311"
			 ">/dev/null 2>/dev/null");
	system(cmd);

	snprintf(cmd, 1024, "/sbin/kextload "
			 "/System/Library/Extensions/AppleAirPortBrcm4311.kext "
			 ">/dev/null 2>/dev/null");
	system(cmd);

	return 1;
}

#endif

