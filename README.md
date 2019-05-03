Wolpd
=====
A Wake-On-LAN Proxy Daemon for Linux
====================================

## Features

* Proxies WOL packets from one interface to an other.

* Proxies either or both raw Ethernet WOL frames as well as UDP WOL
  packets.

* The raw Ethernet Ethertype to listen for can be configured.

* Can listen on all UDP ports or a single UDP port for WOL packets.

* Secure: can be configured to run as a dedicated unprivileged user in
  chroot (root is still required at initialization to open the raw
  socket(s)).

* Efficient: uses socket filters so that all the filtering is done by
  the kernel.  User-space sees only valid WOL frames or packets.

* No third-party dependencies: Uses only libc.

## Configuration & Set-Up

**wolpd** does not have any configurations files.  It can be run
directly from the command line.

When using the default installation, if an init system (whether
_systemd_ or traditional _SysV init_ systems) is detected, **wolpd** will
install the appropriate _systemd_ service file or the _SysV init_ script.

The options used by **wolpd** when started by either _systemd_ or
_SysV init_ can then be configured by changing the `WOLPD_OPTIONS`
line in `/etc/sysconfig/wolpd` or `/usr/local/etc/sysconfig/wolpd`
(the actual location may vary depending on your build prefix).

Before **wolpd** can run successfully by your init system, the
`.../etc/sysconfig/wolpd` file *must be edited* to fill in the input
and output interfaces.

If you use _systemd_, **wolpd** can be started or stopped with:

* For one-time operation (won't restart after a reboot):
``` shell
systemctl start wolpd.service
systemctl stop wolpd.service
```

* For persistent operation (start now and automatically at boot):

``` shell
systemctl enable --now wolpd.service
systemctl disable --now wolpd.service
```

If you use a traditional _SysV init_, please refer to your
distribution's documentation.

**wolpd** comes with an [extensive manual
page](https://htmlpreview.github.io/?https://raw.githubusercontent.com/F-i-f/wolpd/master/wolpd.8.html).

[View](https://htmlpreview.github.io/?https://raw.githubusercontent.com/F-i-f/wolpd/master/wolpd.8.html) or
download the manual page as:
[[HTML]](https://raw.githubusercontent.com/F-i-f/wolpd/master/wolpd.8.html),
[[PDF]](https://raw.githubusercontent.com/F-i-f/wolpd/master/wolpd.8.pdf) or
[[ROFF]](https://raw.githubusercontent.com/F-i-f/wolpd/master/wolpd.8).

## Future directions

* While currently **wolpd** requires a pair of input and output
  interface as arguments, we should be able to forwards a WOL frame
  arriving on _any_ interface to _all_ the other interfaces.

* **wolpd** could also rewrite UDP WOL packets to raw Ethernet WOL
  frames and/or the converse.

## License

wolpd is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see [http://www.gnu.org/licenses/].

## Building from source

### Requirements

* C Compiler (eg. gcc)

* Make (eg. GNU make)

* autotools (autoconf, automake) is only required if building from the
  repository.

* help2man (optional, used to generate the manual page)

* groff is optionally needed to generate the man page hard copies
  (HTML & PDF). It is only needed if you intend to update the manual
  page ROFF or wolpd C sources.

* The provided init scripts and systemd service files assume that a
  user with no privileges named _wolpd_ is present on the system.  You
  can create it with:
  ```shell
  useradd -r -d /var/empty/wolpd -c 'Wake-on-LAN Proxy Daemon' wolpd
  ```
  However this is not required, and you can modify the init script
  and/or systemd service file to run **wolpd** as another user.

### From a release

Download the [latest release from
GitHub](https://github.com/F-i-f/wolpd/releases/download/v1.0.3/wolpd-1.0.3.tar.gz)
or the [secondary mirror](http://ftp.fifi.org/phil/wolpd/wolpd-1.0.3.tar.gz):

* [Primary Site (GitHub)](https://github.com/F-i-f/wolpd/releases/):

  * Source:
	[https://github.com/F-i-f/wolpd/releases/download/v1.0.3/wolpd-1.0.3.tar.gz](https://github.com/F-i-f/wolpd/releases/download/v1.0.3/wolpd-1.0.3.tar.gz)

  * Signature:
	[https://github.com/F-i-f/wolpd/releases/download/v1.0.3/wolpd-1.0.3.tar.gz.asc](https://github.com/F-i-f/wolpd/releases/download/v1.0.3/wolpd-1.0.3.tar.gz.asc)

* [Secondary Site](http://ftp.fifi.org/phil/wolpd/):

  * Source:
	[http://ftp.fifi.org/phil/wolpd/wolpd-1.0.3.tar.gz](http://ftp.fifi.org/phil/wolpd/wolpd-1.0.3.tar.gz)

  * Signature:
	[http://ftp.fifi.org/phil/wolpd/wolpd-1.0.3.tar.gz.asc](http://ftp.fifi.org/phil/wolpd/wolpd-1.0.3.tar.gz.asc)


The source code release are signed with the GPG key ID `0x88D51582`,
available on your [nearest GPG server](https://pgp.mit.edu/) or
[here](http://ftp.fifi.org/phil/GPG-KEY).

You can also find all releases on the [GitHub release
page](https://github.com/F-i-f/wolpd/releases/).  Be careful to
download the source code from the link named with the full file name
(_wolpd-1.0.3.tar.gz_), and **not** from the links marked _Source code
(zip)_ or _Source code (tar.gz)_ as these are repository snapshots
generated automatically by GitHub and require specialized tools to
build (see [Building from GitHub](#from-the-github-repository)).

After downloading the sources, unpack and build with:

```shell
tar xvzf wolpd-1.0.3.tar.gz
cd wolpd-1.0.3
./configure
make
make install
make install-pdf install-html # Optional
```

Alternately, you can create a RPM file by moving the source tar file
and the included `wolpd.spec` in your rpm build directory and running:

```shell
rpmbuild -ba SPECS/wolpd.spec
```

### From the GitHub repository

Clone the [repository](https://github.com/F-i-f/wolpd.git):

```shell
git clone https://github.com/F-i-f/wolpd.git
cd wolpd
autoreconf -i
./configure
make
make install
make install-pdf install-html # Optional
```

## Changelog

### Version 1.0.3
#### May 3, 2019

* Build script-ware and documentation improvements.

### Version 1.0.2
#### April 17, 2019

* Improve logging.

### Version 1.0.1
#### April 16, 2019

* Minor bug fix release: Exit cleanly upon receiving a termination
  signal.

### Version 1.0
#### April 16, 2019

* First release under new management.

## This is a fork

This project is a fork of [wolpd](https://github.com/simon3z/wolpd)
from Federico Simoncelli <federico.simoncelli@gmail.com>.

It has been almost entirely rewritten at this point, and all the blame
should go to the current maintainer (F-i-f).

Please note that since [the original
repository](https://github.com/simon3z/wolpd) was created by a very
old version of git, it does not run `git fsck` successfully.  This
repository contains the same history as the original, but it has been
exported and re-imported so that `git fsck` does not complain.  The
last imported commit from [the original
repository](https://github.com/simon3z/wolpd) is
`6b1c5b63633a2ea66e2ca12d82412af83164f746`, and corresponds to
`07d947c1b7f3fd0db0d5ed4d1d3de8d8665668e4` in this repository.

## Credits

**wolpd** was originally written by Federico Simoncelli <federico.simoncelli@gmail.com>.

It has now almost been completely rewritten by Philippe Troin (F-i-f on GitHub).

<!--  LocalWords:  WOL UDP Ethertype chroot libc wolpd init eg untar
 -->
<!--  LocalWords:  systemd ROFF gcc help2man autotools autoconf GPG
 -->
<!--  LocalWords:  automake Changelog Simoncelli Troin gz github SysV
 -->
<!--  LocalWords:  groff merchantability
 -->
