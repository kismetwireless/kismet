/* From MacStumbler, which is under GPL */

/*
 *  Apple80211.h
 *
 *  This is the reverse engineered header for the Apple80211 private framework.
 *  The framework can be found at /System/Library/PrivateFrameworks/Apple80211.framework.
 *  Linking with Apple80211.framework requires CoreFoundation.framework and AppKit.framework.
 *
 *  Note that there is also information in the IORegistry, see
 *   ioreg -c AirPortDriver -w 0
 *
 *  Contributors:
 *  korben - korben@cox.net
 *  jason - catalyst@mac.com
 *  ragge - ragge@nada.kth.se
 *
 *  Last updated by korben on 5/15/2002
 */
 
 /* ChangeLog:
 
   2002-05-14 ragge
   Changed argument types and count to procedures
   Added WirelessScan
   Changed name of unknown field to beaconInterval
   Added error values and error return types
   
   2002-05-15 korben
   Combined ragge's changes with jason's
   
   2002-05-17 korben
   fixed adhoc and mangaged WINetworkInfoFlags per ragge's request
   Added WirelessEncrypt and WirelessKey declarations
   Updated WirelessJoinWEP and WirelessMakeIBSS comments regarding keys
   
 */

#ifndef __APPLE_80211__
#define __APPLE_80211__

#include <CoreFoundation/CoreFoundation.h>

/*
	A WirelessContext should be created using WirelessAttach
	before any other Wireless functions are called. WirelessDetach
	is used to dispose of a WirelessContext.
*/
typedef struct __WirelessContext *WirelessContextPtr;

struct WirelessInfo
{
	UInt16	link_qual;     /* Link quality, percent? */
	UInt16	comms_qual;    /* Communication Quality */
	UInt16	signal;        /* Signal level */
	UInt16	noise;         /* Noise level */
	UInt16	port_stat;     /* HERMES_RID_PORTSTAT? (Uncertain about the meaning of this! 1=off? 2=connetion bad? 3=AdHoc Create? 4=BSS (Client)? 5=BSS+OutOfRange?) */
	UInt16	client_mode;   /* 1 = BSS, 4 = Create IBSS */
	UInt16	u7;            /* ? */
	UInt16	power;         /* Power on flag */
	UInt16	u9;            /* 0=bad?, 1=ok?, 2=wrong key? */
	UInt8	macAddress[6]; /* MAC address of wireless access point. */
	SInt8	name[34];      /* Name of current (or wanted?) network. */
};
typedef struct WirelessInfo WirelessInfo;
/*
	I'm not sure what most of the values in the WirelessInfo structure
	are for, but here are some examples of the numbers returned:
	
	With Airport Off:
	0 0 0 0 1 1 0 0 1

	With Airport On:
	72 22 31 9 4 1 0 1 1

	With Computer to Computer Network:
	0 0 0 0 3 4 0 1 1
	
	- jason
*/


/*
	WINetworkInfoFlags are used in the WirelessNetworkInfo struct
	returned by the WirelessScanSplit function.
	
	I have seen other flags, but I don't know what they stand for. - korben
	
	I think these should probably be bit masks, but I am using what
	korben figured out. - jason
*/
typedef UInt16 WINetworkInfoFlags;
enum
{
	kWINetworkManagedFlag =   0x0001,
	kWINetworkAdhocFlag =     0x0002,
	kWINetworkEncryptedFlag = 0x0010
};

typedef SInt32 WIErr;
enum {
  airpParamErr        = -2013261823, /* 0x88001001 */
  airpNoIOServiceErr  = -2013261822, /* 0x88001002 */
  airpInternalErr     = -2013261821, /* 0x88001003 */
  airpUnk4Err         = -2013261820, /* 0x88001004 */
  airpOutOfMemErr     = -2013261819, /* 0x88001005 */
  airpInternal2Err    = -2013261818, /* 0x88001006 */
  airpUnk7Err         = -2013261817, /* 0x88001007 */
  airpUnk8Err         = -2013261816, /* 0x88001008 */
  airpUnk9Err         = -2013261815, /* 0x88001009 */
  airpUnkaErr         = -2013261814, /* 0x8800100a */
  airpNoPowerErr      = -2013261813  /* 0x8800100b */
};
/* The meaning of these error codes can be wrong, and the list is not
 * complete. In general checking for noErr (0) should be enough */

struct WirelessNetworkInfo
{
	UInt16					channel; /* Channel for the network. */
	UInt16					noise; /* Noise for the network. 0 for Adhoc. */
	UInt16					signal; /* Signal strength of the network. 0 for Adhoc. */
	UInt8					macAddress[6]; /* MAC address of the wireless access point. */
	UInt16					beaconInterval; /* beacon interval in milliseconds */
	WINetworkInfoFlags			flags; /* Flags for the network. */
	UInt16					nameLen;
	SInt8					name[32];
};
typedef struct WirelessNetworkInfo WirelessNetworkInfo;

typedef UInt8 WirelessKey[13]; // For use with WirelessEncrypt


/*
 *  WirelessIsAvailable()
 *
 *  Returns 1 if a wireless interface is available, 0 otherwise
 */
extern int WirelessIsAvailable(void);

/*
 *  WirelessAttach()
 *  
 *  WirelessAttach should be called before all other Wireless functions.
 *
 *  outContext returns the contextPtr you will pass
 *  to all other Wireless functions
 *  The second argument must be zero.
 */
extern WIErr WirelessAttach(
	WirelessContextPtr *outContext,
	const UInt32);

/*
 *  WirelessDetach()
 *
 *  WirelessDetach is called after you are done calling Wireless functions.
 *  It will free all memory being used by the library.
 *
 *  inContext is the contextPtr you want to dispose of.
 */
extern WIErr WirelessDetach(
	WirelessContextPtr inContext);

/*
 *  WirelessGetPower()
 *
 *  WirelessGetPower returns the power state of Airport.
 *
 *  inContext is the contextPtr created by WirelessAttach.
 *  outPower is 0 for off and 1 for on.
 */
extern WIErr WirelessGetPower(
	WirelessContextPtr inContext,
	UInt8 *outPower);

/*
 *  WirelessSetPower()
 *
 *  WirelessSetPower will turn Airport on or off.
 *
 *  inContext is the contextPtr created by WirelessAttach.
 *  inPower is 0 for off and 1 for on.
 */
extern WIErr WirelessSetPower(
	WirelessContextPtr inContext,
	UInt8 inPower);

/*
 *  WirelessGetEnabled()
 *
 *  WirelessGetEnabled could have returned the Enabled state of Airport,
 *  but it seems to rather return the Power state.
 *
 *  inContext is the contextPtr created by WirelessAttach.
 *  outEnabled is 0 for off and 1 for on.
 */
extern WIErr WirelessGetEnabled(
	WirelessContextPtr inContext,
	UInt8 *outEnabled);

/*
 *  WirelessSetEnabled()
 *
 *  WirelessSetEnabled will enable or disable Airport communication.
 *
 *  inContext is the contextPtr created by WirelessAttach.
 *  inEnabled is 0 for off and 1 for on.
 */
extern WIErr WirelessSetEnabled(
	WirelessContextPtr inContext,
	UInt32 inEnabled);

/*
 *  WirelessGetInfo()
 *
 *  WirelessGetInfo returns info about the state
 *  of the current wireless connection.
 *
 *  inContext is the contextPtr created by WirelessAttach.
 *  outInfo is a WirelessInfo structure containing state info.
 */
extern WIErr WirelessGetInfo(
	WirelessContextPtr inContext,
	WirelessInfo *outInfo);

/*
 *  WirelessScanSplit(), WirelessScan()
 *
 *  WirelessScanSplit scans for available wireless networks.
 *  It will allocate 2 CFArrays to store a list
 *  of managed and adhoc networks. The arrays hold CFData
 *  objects which contain WirelessNetworkInfo structures.
 *  Note: An adhoc network created on the computer the
 *  scan is running on will not be found. WirelessGetInfo
 *  can be used to find info about a local adhoc network.
 *
 *  inContext is the contextPtr created by WirelessAttach.
 *  apList will contain a CFArrayRef of managed networks.
 *  adhocList will contain a CFArrayRef of adhoc networks.
 *  For example:
 *  WirelessScanSplit(clientContext, &apList, &adhocList, 1)
 *
 *  If stripDups != 0 only one basestation for each SSID will be returned
 *
 *  WirelessScan works the same way but does not split the list by AP type
 */
extern WIErr WirelessScanSplit(
	WirelessContextPtr inContext,
	CFArrayRef *apList,
	CFArrayRef *adhocList,
	const UInt32 stripDups);
	
extern WIErr WirelessScan(
	WirelessContextPtr inContext,
	CFArrayRef *apList,
	const UInt32 stripDups);

/*
 *  WirelessJoin()
 *
 *  WirelessJoin is used to join a Wireless network.
 *
 *  inContext is the contextPtr created by WirelessAttach.
 *  inNetworkName is the name of the network to join.
 */
extern WIErr WirelessJoin(
	WirelessContextPtr inContext,
	CFStringRef inNetworkName);

/*
 *  WirelessJoinWEP()
 *
 *  WirelessJoinWEP is used to join an encrypted network.
 *
 *  inContext is the contextPtr created by WirelessAttach.
 *  inNetworkName is the name of the network to join.
 *  inNetworkPassword is the password/key of the network.
 *
 *  inNetworkPassword description:
 *  - Passwords are just a string of any length, they will be hashed into a key.
 *  - Keys should be passed as a hex string, optionally beginning with 0x,
 *    and must be either 10 digits for a 40bit key or 26 digits for a 104bit key,
 *    or an ascii/binary representation of the key, 5 or 13 bytes long.
 *  - It can also be the empty string, meaning no encryption.
 *  
 *  For more info see:
 *  http://kbase.info.apple.com/cgi-bin/WebObjects/kbase.woa/11/wa/query?searchMode=Expert&type=id&val=KC.106424
 */
extern WIErr WirelessJoinWEP(
	WirelessContextPtr inContext,
	CFStringRef inNetworkName,
	CFStringRef inNetworkPassword);

/*
 *  WirelessEncrypt
 *
 *  WirelessEncrypt is called from WirelessJoinWEP and
 *  WirelessMakeIBSS to translate a string into a 40 or
 *  104-bit Apple hashed WEP key.
 *  Third argument is 0 for 40 bit key and 1 for 104 bit key.
 *
 *  Sample usage:
 *
 *  WirelessKey myKey;
 *  WirelessEncrypt(@"password", &myKey, 1);
 *  for(int i=0; i <= 12; i++)
 *  	printf("%.2X ", myKey[i]);
 *
 */
extern WIErr WirelessEncrypt(
        CFStringRef inNetworkPassword,
        WirelessKey *wepKey,
        const UInt32 use104bits);

/*
 *  WirelessGetChannels()
 *
 *  WirelessGetChannels is used to get valid channels for
 *  creating an adhoc network.
 *
 *  inContext is the contextPtr created by WirelessAttach.
 *  outChannelBitField contains a bit field of valid channels.
 *  For example if 0x07FF is returned then bits 0 through 10
 *  are set, which means channels 1 through 11 are valid.
 */
extern WIErr WirelessGetChannels(
	WirelessContextPtr inContext,
	UInt16 *outChannelBitField);

/*
 *  WirelessGetBestChannel()
 *
 *  WirelessGetBestChannel is used to get the best channel
 *  for creating an adhoc network on.
 *
 *  inContext is the contextPtr created by WirelessAttach.
 *  outBestChannel is the best channel for a wireless network.
 */
extern WIErr WirelessGetBestChannel(
	WirelessContextPtr inContext,
	UInt16 *outBestChannel);

/*
 *  WirelessMakeIBSS()
 *
 *  WirelessMakeIBSS is used to create a computer to computer
 *  adhoc wireless network.
 *
 *  inContext is the contextPtr created by WirelessAttach.
 *  inNetworkName is the name of the network to create.
 *  inNetworkPassword is the password/key for the new network.
 *  inChannel is the wireless channel the network will use.
 *
 *  inNetworkPassword description:
 *  - Passwords are just a string of any length, they will be hashed into a key.
 *  - Keys should be passed as a hex string, optionally beginning with 0x,
 *    and must be either 10 digits for a 40bit key or 26 digits for a 104bit key.
 *  - It can also be the empty string, meaning no encryption.
 *  
 *  For more info see:
 *  http://kbase.info.apple.com/cgi-bin/WebObjects/kbase.woa/11/wa/query?searchMode=Expert&type=id&val=KC.106424
 */
extern WIErr WirelessMakeIBSS(
	WirelessContextPtr inContex,
	CFStringRef inNetworkName,
	CFStringRef inNetworkPassword,
	UInt32 inChannel);

/*
 *  Get information from the Hermes chip.
 *  
 *  RIDno is the Hermes RID number for the data to get, as
 *  0xFC01 - HERMES_RID_CNFOWNMACADDR
 *  0xFC02 - HERMES_RID_CNFDESIREDSSID
 *  0xFDC1 - HERMES_RID_CURRENTCHANNEL
 *  and so on.
 *  Don't know why, but 0xF100 - HERMES_INQ_TALLIES works here too,
 *  and a struct with the counters will be returned. (The data
 *  returned seems to be lagging, though, call twice for fresh data.)
 */
extern WIErr WirelessHCF_GetInfo(
	WirelessContextPtr inContext,
	UInt16 RIDno,
	UInt32 outBufSize,
	void *outBuf);


/*
	***** MISSING FUNCTIONS *****
	
	These functions are used to configure an Access Point (Base Station).
	Most of these are used by the Airport Admin Utility.app, and some like
	WirelessAP_GetStatus are even used by Internet Connect.app. - jason
	
		WirelessAP_BinaryCurrentVersion
		WirelessAP_BinaryCurrentVersion2
		WirelessAP_BinaryIsCurrent
		WirelessAP_BinaryUpload
		WirelessAP_BinaryUploadACP
		WirelessAP_BinaryVersion
		WirelessAP_Dial
		WirelessAP_DialDynamic
		WirelessAP_Explore
		WirelessAP_ForceIPAddress
		WirelessAP_GetBridgeStatus
		WirelessAP_GetCommonVariables
		WirelessAP_GetCommonVariablesACP
		WirelessAP_GetFullStatus
		WirelessAP_GetModemVersion
		WirelessAP_GetModemVersionACP
		WirelessAP_GetStatus
		WirelessAP_GetType
		WirelessAP_GetVersion
		WirelessAP_Hangup
		WirelessAP_IsConnected
		WirelessAP_Read
		WirelessAP_ReadACP
		WirelessAP_ResetNVRAM
		WirelessAP_Restart
		WirelessAP_RestartACP
		WirelessAP_Write
		WirelessAP_WriteACP
	
	I can't find any apps that use these functions. - jason
	
		WirelessAccessPoint
		WirelessConfigure
		WirelessDownloadFW
		WirelessSetKey
*/

extern WIErr WirelessPrivate(WirelessContextPtr inContext,void* in_ptr,int in_bytes,void* out_ptr,int  out_bytes);

#endif // __APPLE_80211__
