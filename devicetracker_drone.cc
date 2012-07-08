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

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <sstream>

#include "globalregistry.h"
#include "util.h"
#include "configfile.h"
#include "messagebus.h"
#include "packetchain.h"
#include "devicetracker.h"
#include "packet.h"
#include "gpswrapper.h"
#include "alertracker.h"
#include "manuf.h"
#include "packetsourcetracker.h"
#include "packetsource.h"
#include "dumpfile_devicetracker.h"

Devicetracker::Devicetracker(GlobalRegistry *in_globalreg) {
}

Devicetracker::~Devicetracker() {
}

void Devicetracker::SaveTags() {
}

vector<kis_tracked_device *> *Devicetracker::FetchDevices(int in_phy) {
	return NULL;
}

Kis_Phy_Handler *Devicetracker::FetchPhyHandler(int in_phy) {
	return NULL;
}

int Devicetracker::FetchNumDevices(int in_phy) {
	return 0;
}

int Devicetracker::FetchNumPackets(int in_phy) {
	return 0;
}

int Devicetracker::FetchNumDatapackets(int in_phy) {
	return 0;
}

int Devicetracker::FetchNumCryptpackets(int in_phy) {
	return 0;
}

int Devicetracker::FetchNumErrorpackets(int in_phy) {
	return 0;
}

int Devicetracker::FetchNumFilterpackets(int in_phy) {
	return 0;
}

int Devicetracker::FetchPacketRate(int in_phy) {
	return 0;
}

int Devicetracker::RegisterDeviceComponent(string in_component) {
	return -1;
}

int Devicetracker::RegisterPhyHandler(Kis_Phy_Handler *in_weak_handler) {
	return -1;
}

// Send all devices to a client
void Devicetracker::BlitDevices(int in_fd) {
}

void Devicetracker::BlitPhy(int in_fd) {
}

int Devicetracker::TimerKick() {
	return 0;
}

kis_tracked_device *Devicetracker::FetchDevice(mac_addr in_device) {
	return NULL;
}

kis_tracked_device *Devicetracker::FetchDevice(mac_addr in_device, 
											   unsigned int in_phy) {
	return NULL;
}

int Devicetracker::StringCollector(kis_packet *in_pack) {
	return 0;
}

int Devicetracker::CommonTracker(kis_packet *in_pack) {
	return 0;
}

// Find a device, creating the device as needed and populating common data
kis_tracked_device *Devicetracker::MapToDevice(mac_addr in_device, 
											   kis_packet *in_pack) {
	return NULL;
}

// Find a device, creating the device as needed and populating common data
kis_tracked_device *Devicetracker::BuildDevice(mac_addr in_device, 
											   kis_packet *in_pack) {
	return NULL;
}

int Devicetracker::PopulateCommon(kis_tracked_device *device, kis_packet *in_pack) {
	return 0;
}

void Devicetracker::WriteXML(FILE *in_logfile) {
}

void Devicetracker::WriteTXT(FILE *in_logfile) {

}

int Devicetracker::LogDevices(string in_logclass, 
							  string in_logtype, FILE *in_logfile) {
	return 0;
}

int Devicetracker::SetDeviceTag(mac_addr in_device, string in_tag, string in_data,
								 int in_persistent) {
	return -1;
}

int Devicetracker::ClearDeviceTag(mac_addr in_device, string in_tag) {
	return -1;
}

string Devicetracker::FetchDeviceTag(mac_addr in_device, string in_tag) {
	return "";
}

