#  wolpd - Wake-On-LAN Proxy Daemon
#  Makefile.am
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

ACLOCAL_AMFLAGS = -I m4

sbin_PROGRAMS   = wolpd

wolpd_SOURCES   = wolpd.c

dist_man8_MANS  = wolpd.8

EXTRA_DIST	= wolpd.init.in \
		  wolpd.service.in \
		  wolpd.spec \
		  wolpd.sysconfig \
		  wolpd.h2m

keep_generated_files       = wolpd.8
expendable_generated_files = wolpd.init wolpd.service
all_generated_files        = $(keep_generated_files) $(expendable_generated_files)

all-local: $(all_generated_files)

wolpd.8: $(srcdir)/wolpd.c $(srcdir)/wolpd.h2m
	-$(HELP2MAN) -i $(srcdir)/wolpd.h2m -o $@ ./wolpd

wolpd.init wolpd.service: Makefile
	sed -e 's![@]sbindir@!$(sbindir)!g' \
	    -e 's![@]sysconfdir@!$(sysconfdir)!g' $(srcdir)/$@.in > $@

wolpd.init: wolpd.init.in
wolpd.service: wolpd.service.in

# Install
install-data-local: install-data-local-init install-data-local-sysconfig

install-data-local-init: wolpd.service wolpd.init
	@if systemctl --version >& /dev/null; \
	then \
	  unitpath="$$(systemctl show \
		       | grep '^UnitPath=' \
		       | sed -e 's!^UnitPath=!!' \
			     -e 's! !\n!g' \
		       | egrep -v '/(etc($|/)|run/)')"; \
	  if [ -d "$$unitpath" -a -w "$$unitpath" ]; \
	  then \
	    ( set -x; \
	      $(INSTALL) -d "$(DESTDIR)$$unitpath" \
	      && $(INSTALL_DATA) wolpd.service "$(DESTDIR)$$unitpath/wolpd.service" ); \
	  fi; \
	else \
	  for d in /etc/init.d/rc.d /etc/init.d; \
	  do \
	    if [ -d "$$d" -a -w "$$d" ]; \
	    then \
	      (set -x; \
		$(INSTALL) -d "$(DESTDIR)$$d" \
		&& $(INSTALL) wolpd.init "$(DESTDIR)$$d/wolpd.init" ); \
	      exit $$?; \
	    fi; \
	  done; \
	fi

install-data-local-sysconfig:
	$(INSTALL) -d "$(DESTDIR)$(sysconfdir)/sysconfig"
	$(INSTALL_DATA) $(srcdir)/wolpd.sysconfig "$(DESTDIR)$(sysconfdir)/sysconfig/wolpd"

# Uninstall
uninstall-local: uninstall-local-init uninstall-local-sysconfig

uninstall-local-init:
	@if systemctl --version >& /dev/null; \
	then \
	  unitpath="$$(systemctl show \
		       | grep '^UnitPath=' \
		       | sed -e 's!^UnitPath=!!' \
			     -e 's! !\n!g' \
		       | egrep -v '/(etc($|/)|run/)')"; \
	  if [ -d "$$unitpath" -a -w "$$unitpath" ]; \
	  then \
	    ( set -x; \
	      rm -f "$(DESTDIR)$$unitpath/wolpd.service" ); \
	  fi; \
	else \
	  for d in /etc/init.d/rc.d /etc/init.d; \
	  do \
	    if [ -d "$$d" -a -w "$$d" ]; \
	    then \
	      (set -x; \
		rm -f "$(DESTDIR)$$d/wolpd.init" ); \
	      exit $$?; \
	    fi; \
	  done; \
	fi

uninstall-local-sysconfig:
	rm -f "$(DESTDIR)$(sysconfdir)/sysconfig/wolpd"

# Clean & misc
CLEANFILES	     = $(expendable_generated_files)
MAINTAINERCLEANFILES = $(keep_generated_files)

.PHONY: all-local install-local install-local-init install-local-sysconfig
.PHONY: uninstall-local uninstall-local-init uninstall-local-sysconfig

@FI_AUTOMAKE@
