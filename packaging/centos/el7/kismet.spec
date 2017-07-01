%define major 2016
%define minor 07
%define micro 1

Summary: An 802.11 network sniffer and network dissector.
Name: kismet
Version: %{major}.%{minor}.%{micro}
Release: 1%{?dist}
Group: Networking/Utilities
License: GPL
Url: www.kismetwireless.net
Source: https://kismetwireless.net/code/kismet-%{major}-%{minor}-R%{micro}.tar.xz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires: ncurses-devel libpcap-devel libnl-devel pcre-devel bluez-libs-devel libcap-devel 
Requires: bluez-libs libnl libpcap libcap
Requires(pre): shadow-utils
Provides: kismet
Conflicts: kismet-git

%description
Kismet is an 802.11 wireless network detector, sniffer, and intrusion
detection system.  Kismet will work with any wireless card which 
supports raw monitoring mode, and can sniff 802.11b, 802.11a, 802.11g, 
and 802.11n traffic (devices and drivers permitting).

%prep
%setup -q -n %{name}-%{major}-%{minor}-R%{micro}

%build
%configure

%{__make} dep all plugins

%install
%{__make} DESTDIR=%{buildroot}/ rpm 

install kismet_capture %{buildroot}/usr/bin
install -D plugin-alertsyslog/alertsyslog.so %{buildroot}/usr/lib64/kismet/alertsyslog.so
install -D plugin-btscan/btscan.so %{buildroot}/usr/lib64/kismet/btscan.so
install -D plugin-btscan/btscan_ui.so %{buildroot}/usr/lib64/kismet_client/btscan_ui.so
install -D plugin-syslog/kismet-syslog.so %{buildroot}/usr/lib64/kismet/kistmet-syslog.so
install -D plugin-spectools/spectool_net.so %{buildroot}/usr/lib64/kismet/spectool_net.so
install -D plugin-spectools/spectools_ui.so %{buildroot}/usr/lib64/kismet_client/spectools_ui.so

%pre
getent group kismet >/dev/null || groupadd -r kismet

%files
%defattr(-,root,root)
%doc README 
%doc RELEASENOTES.txt
%doc docs/DEVEL.client
%doc docs/README.newcore
%doc docs/devel-wiki-docs/*.wiki
%config /etc/kismet.conf
%config /etc/kismet_drone.conf
/usr/bin/kismet
/usr/bin/kismet_client
/usr/bin/kismet_server
/usr/bin/kismet_drone
%attr(4550,root,kismet) /usr/bin/kismet_capture
/usr/share/man/man1/*
/usr/share/man/man5/*
/usr/share/kismet/wav/new.wav
/usr/share/kismet/wav/packet.wav
/usr/share/kismet/wav/alert.wav
/usr/share/kismet/wav/gpslost.wav
/usr/share/kismet/wav/gpslock.wav
/usr/lib64/kismet/alertsyslog.so
/usr/lib64/kismet/btscan.so
/usr/lib64/kismet/kistmet-syslog.so
/usr/lib64/kismet/spectool_net.so
/usr/lib64/kismet_client/btscan_ui.so
/usr/lib64/kismet_client/spectools_ui.so

%changelog
* Sat Jul 01 2017 Michael Hubbard <mhubbard@binarygrove.com> - 2016-07-R1
- Initial RPM spec file.
