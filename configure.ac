#  wolpd - Wake-On-LAN Proxy Daemon
#  configure.ac
#  Copyright (C) 2010  Federico Simoncelli <federico.simoncelli@gmail.com>
#  Copyright (C) 2019  Philippe Troin (F-i-f onj GitHub)
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

AC_INIT([wolpd], [1.0.6], [https://github.com/F-i-f/wolpd/issues])
AC_CONFIG_AUX_DIR([config.aux])
FI_PROJECT()

# Get started
AC_CONFIG_SRCDIR([wolpd.c])
AC_LANG([C])

### 1) Checking for system
AC_USE_SYSTEM_EXTENSIONS

### 2) Checking for programs
AC_PROG_CC
FI_COMPILER_WARNINGS
AM_MISSING_PROG([HELP2MAN], [help2man])
FI_FORMAT_MAN([wolpd.8], [html pdf])

FI_GIT_REVISION

# Output
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
