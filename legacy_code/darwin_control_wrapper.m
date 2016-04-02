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
#include "apple80211.h"
#include <Carbon/Carbon.h>
#include "darwin_control_wrapper.h"
#import "darwin_wificontrol.h"


int darwin_bcom_testmonitor()
{
	NSDictionary *dict;
	NSData *fileData;
	NSString *error;
	NSAutoreleasePool *pool;	
	pool  = [[NSAutoreleasePool alloc] init];

	fileData = [NSData dataWithContentsOfFile:@"/System/Library/PrivateFrameworks/AppleTV.framework/Versions/Current/Resources/Info.plist"];
	dict = [NSPropertyListSerialization propertyListFromData:fileData mutabilityOption:kCFPropertyListImmutable format:NULL errorDescription:&error];
	if(!dict)
	{
		NSLog(@"%s", error);
	}
	else
	{
		if (strcmp([[dict valueForKeyPath:@"CFBundleExecutable"] cString], "AppleTV") == 0) return 1;
	}
	// This may work on AppleTV 1.1 also but I am not sure. This is a quick hack to force 1.0 to work. 
	fileData = [NSData dataWithContentsOfFile:@"/System/Library/MonitorPanels/AppleDisplay.monitorPanels/Contents/Resources/TVOptions.monitorPanel/Contents/Info.plist"];
	dict = [NSPropertyListSerialization propertyListFromData:fileData mutabilityOption:kCFPropertyListImmutable format:NULL errorDescription:&error];
	if(!dict)
	{
		NSLog(@"%s", error);
	}
	else
	{
		if (strcmp([[dict valueForKeyPath:@"CFBundleExecutable"] cString], "TVOptions") == 0) return 1;
	}
	fileData = [NSData dataWithContentsOfFile:@"/System/Library/Extensions/AppleAirPort2.kext/Contents/Info.plist"];
	dict = [NSPropertyListSerialization propertyListFromData:fileData mutabilityOption:kCFPropertyListImmutable format:NULL errorDescription:&error];
	if(!dict)
	{
		NSLog(@"%s", error);
	}
	else
	{

		if ([[dict valueForKeyPath:@"IOKitPersonalities.Broadcom PCI.APMonitorMode"] boolValue]) return 1;
	}	
	fileData = [NSData dataWithContentsOfFile:@"/System/Library/Extensions/IO80211Family.kext/Contents/PlugIns/AppleAirPortBrcm4311.kext/Contents/Info.plist"];
	dict = [NSPropertyListSerialization propertyListFromData:fileData mutabilityOption:kCFPropertyListImmutable format:NULL errorDescription:&error];
	if(!dict)
	{
		NSLog(@"%s", error);
	}
	else
	{
		if ([[dict valueForKeyPath:@"IOKitPersonalities.Broadcom PCI.APMonitorMode"] boolValue]) return 1;
	}
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
	int ret, i;
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
	fprintf(stderr, "ATTENTION:  Kismet has enabled rfmon on your devices, however "
			"to activate it, the kernel modules must be reloaded.  There have "
			"been reports of this causing a system crash.  Kismet will wait 10 "
			"seconds before attempting to reload the kernel modules.  Press "
			"control-c now to cancel reloading modules and reboot manually if "
			"you do not want to proceed!\n\n");

	sleep(10);

	/* we don't check the failure codes since we don't know which driver we're 
	 * using... Also according to geordi we have to thrash the unload because
	 * sometimes it just refuses to unload the module.  Highly inelegant. */
	for (i = 0; i < 10; i++) {
		snprintf(cmd, 1024, "/sbin/kextunload -b com.apple.driver.AppleAirPort2"
				 ">/dev/null 2>/dev/null");
		system(cmd);

		snprintf(cmd, 1024, "/sbin/kextunload -b "
				 "com.apple.driver.AppleAirPortBrcm4311 >/dev/null 2>/dev/null");
		system(cmd);
	}

	/* Try to reload them */
	snprintf(cmd, 1024, "/sbin/kextload /System/Library/Extensions/AppleAirPort2.kext"
			 ">/dev/null 2>/dev/null");
	system(cmd);

	snprintf(cmd, 1024, "/sbin/kextload "
			 "/System/Library/Extensions/AppleAirPortBrcm4311.kext "
			 ">/dev/null 2>/dev/null");
	system(cmd);

	fprintf(stderr, "ATTENTION:  Completed trying to reload the kernel modules.  "
			"Sometimes this doesn't work, if Kismet does not start properly "
			"you will need to manually reboot.\n");
	sleep(5);

	return 1;
}

void *darwin_allocate_interface(const char *in_iface) {
	DarwinWifi *darwin = [[DarwinWifi alloc] initWithInterface:[[NSString alloc] initWithUTF8String:in_iface]];

	return (void *) darwin;
}

void darwin_free_interface(void *in_darwin) {
	// TODO
}

int darwin_set_channel(unsigned int in_channel, char *ret_err, void *in_darwin) {
	DarwinWifi *darwin = (DarwinWifi *) in_darwin;
	BOOL result;
	NSError *err;

	result = [darwin setChannel:in_channel error:ret_err];

	if (!result) {
		return -1;
	}

	return 1;
}

int darwin_get_corewifi(void *in_darwin) {
	DarwinWifi *darwin = (DarwinWifi *) in_darwin;

	return [darwin getCoreWireless];
}

void darwin_disassociate(void *in_darwin) {
	DarwinWifi *darwin = (DarwinWifi *) in_darwin;

	[darwin disAssociate];
}

int darwin_get_channels(const char *in_iface, int **ret_channels) {
	NSArray *supported;
	int *ret = NULL;
	int x = 0;

	DarwinWifi *darwin = [[DarwinWifi alloc] initWithInterface:[[NSString alloc] initWithUTF8String:in_iface]];

	supported = [darwin getSupportedChannels];

	if (supported == nil) {
		*ret_channels = NULL;
		return 0;
	}

	ret = (int *) malloc(sizeof(int) * [supported count]);

	for (id sup in supported) {
		ret[x++] = [sup intValue];
	}

	*ret_channels = ret;

	x = [supported count];

	return x;
}

#endif

