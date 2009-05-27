Summary: Kismet is an 802.11 network sniffer and network dissector.
Name: kismet
Version: 2004.03
Release: 1
Group: Networking/Utilities
Copyright: GPL
Url: www.kismetwireless.net
Source: kismet-%{version}.%{release}.tar.gz
BuildRoot: %{_tmppath}/%{name}-root


%description
Kismet is an 802.11 layer2 wireless network detector, sniffer, and
intrusion detection system.  Kismet will work with any wireless card which
supports raw monitoring (rfmon) mode, and can sniff 802.11b, 802.11a, and
802.11g traffic.


%prep
%setup -q


%build
%configure

make


%install
rm -rf $RPM_BUILD_ROOT

make DESTDIR=$RPM_BUILD_ROOT/ rpm


#%clean
#rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc README docs/DEVEL.*
%config /etc/kismet.conf
%config /etc/kismet_ui.conf
%config /etc/kismet_drone.conf
/etc/ap_manuf
/etc/client_manuf
/usr/bin/kismet
/usr/bin/kismet_client
/usr/bin/kismet_drone
%attr(0755,root,root) /usr/bin/kismet_server
%attr(0755,root,root) /usr/bin/kismet_drone
/usr/share/kismet/wav/*.wav
/usr/share/man/man1/gpsmap.1.gz
/usr/share/man/man1/kismet.1.gz
/usr/share/man/man1/kismet_drone.1.gz
/usr/share/man/man5/kismet.conf.5.gz
/usr/share/man/man5/kismet_ui.conf.5.gz
/usr/share/man/man5/kismet_drone.conf.5.gz

%changelog
* Wed Aug 21 2002 Jeremiah Johnson <jjohnson@sunrise-linux.com>
- Initial specfile creation.
* Sat Sep 21 2002 Mike Kershaw <dragorn@kismetwireless.net>
- Added manuf tag files, additional man files
* Mon Feb 24 2002 Mike Kershaw <dragorn@kismetwireless.net>
- Added drone man files and kismet_drone binary
* Sat Mar 13 2004 Mike Kershaw <dragorn@kismetwireless.net>
- Updated spec file (finally), removed suid install, updated other info
