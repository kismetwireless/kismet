Summary: Kismet is an 802.11b network sniffer and network dissector.
Name: kismet
Version: devel
Release: 1
Group: Networking/Utilities
Copyright: GPL
Url: www.kismetwireless.net
Source: kismet-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-root


%description
Kismet is an 802.11b network sniffer and network dissector. It is
capable of sniffing using most wireless cards, automatic network IP
block detection via UDP, ARP, and DHCP packets, Cisco equipment lists
via Cisco Discovery Protocol, weak cryptographic packet logging, and
Ethereal and tcpdump compatible packet dump files. It also includes
the ability to plot detected networks and estimated network ranges on
downloaded maps or user supplied image files.


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
%doc docs/CARD.* docs/DEVEL.* docs/README.*
%config /etc/kismet.conf
%config /etc/kismet_ui.conf
/etc/ap_manuf
/etc/client_manuf
/usr/bin/kismet
/usr/bin/kismet_curses
/usr/bin/kismet_hopper
/usr/bin/kismet_monitor
%attr(4755,root,root) /usr/bin/kismet_server
/usr/bin/kismet_unmonitor
/usr/share/kismet/wav/*.wav
/usr/share/man/man1/gpsmap.1.gz
/usr/share/man/man1/kismet.1.gz
/usr/share/man/man1/kismet_monitor.1.gz
/usr/share/man/man5/kismet.conf.5.gz
/usr/share/man/man5/kismet_ui.conf.5.gz

%changelog
* Wed Aug 21 2002 Jeremiah Johnson <jjohnson@sunrise-linux.com>
- Initial specfile creation.
* Sat Sep 21 2002 Mike Kershaw <dragorn@kismetwireless.net>
- Added manuf tag files, additional man files
