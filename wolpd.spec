Name:		wolpd
Version:	1.0.4
Release:	1%{?dist}
Summary:	Wake-On-Lan Proxy Daemon

Group:          System Environment/Daemons
License:	GPLv3+
URL:		https://github.com/F-i-f/wolpd/
Source0:	%{name}-%{version}.tar.gz

%{?systemd_requires}

BuildRequires:  help2man
BuildRequires:  systemd

%description
Wake-on-LAN is an Ethernet computer networking standard that allows a
computer to be turned on or woken up by a network message. The message
is usually sent by a simple program executed on another computer on
the local area network.

WOL packets are not forwarded by routers, which is where wolpd comes
into play, by proxying WOL packets from one network to an other.
wolpd can forward either or both raw Ethernet WOL frames and UDP WOL
packets.

%prep
%setup -q

%build
%configure --enable-compiler-warnings
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
%make_install

%post
useradd -r -d /var/empty/wolpd -c 'Wake-on-LAN Proxy Daemon' %{name} >& /dev/null || :
%systemd_post wolpd.service

%preun
%systemd_preun wolpd.service
if [ $1 -eq 0 ] ; then
  userdel %{name} >& /dev/null || :
fi

%postun
%systemd_postun_with_restart wolpd.service

%files
%defattr(-,root,root,-)
%config(noreplace) %{_sysconfdir}/sysconfig/%{name}
%{_sbindir}/%{name}
%{_unitdir}/%{name}.service
%{_mandir}/man*/%{name}.*
%{_docdir}/%{name}
%dir %{_localstatedir}/empty/%{name}

%changelog
* Wed May 22 2019 Philippe Troin <phil@fifi.org> - 1.0.4-1
- Upstream updated to 1.0.4.

* Fri May  3 2019 Philippe Troin <phil@fifi.org> - 1.0.3-1
- Upstream updated to 1.0.3.
- Rely on make install to install documentation files.
- Do not autoreconf, it's unneeded.
- Use compiler warnings in configure.

* Wed Apr 17 2019 Philippe Troin <phil@fifi.org> - 1.0.2-1
- Upstream updated to 1.0.2.

* Wed Apr 17 2019 Philippe Troin <phil@fifi.org> - 1.0.1-1
- Upstream updated to 1.0.1.

* Tue Apr 16 2019 Philippe Troin <phil@fifi.org> - 1.0-1
- New upstream release 1.0.

* Sun Jun 19 2016 Federico Simoncelli <fsimonce@redhat.com> 0.5.2-1
- new package built with tito

* Thu Jun 2 2016 Federico Simoncelli <federico.simoncelli@gmail.com> 0.5.1-1
- update to 0.5.1

* Fri Feb 12 2010 Federico Simoncelli <federico.simoncelli@gmail.com> 0.5.0-1
- first release
