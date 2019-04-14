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

AC_PREREQ([2.63])
AC_INIT([wolpd], [0.5.1], [federico.simoncelli@gmail.com])
AC_CONFIG_AUX_DIR([config.aux])
AM_INIT_AUTOMAKE()
AC_CONFIG_SRCDIR([wolpd.c])
AC_CONFIG_HEADERS([config.h])

AC_USE_SYSTEM_EXTENSIONS
AM_MISSING_PROG(HELP2MAN, help2man)

# Checks for programs.
AC_PROG_CC

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
