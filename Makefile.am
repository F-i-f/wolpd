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

EXTRA_DIST	= wolpd.8.html \
		  wolpd.8.pdf \
		  wolpd.init.in \
		  wolpd.service.in \
		  wolpd.spec \
		  wolpd.sysconfig \
		  wolpd.h2m

keep_generated_files       = wolpd.8
expendable_generated_files = wolpd.init wolpd.service
all_generated_files        = $(keep_generated_files) $(expendable_generated_files)

.PHONY: all-local
all-local: $(all_generated_files)

wolpd.8: $(srcdir)/wolpd.c $(srcdir)/wolpd.h2m $(srcdir)/configure.ac
	-$(HELP2MAN) -i $(srcdir)/wolpd.h2m -o $@ ./wolpd \
	   --version-string="$$(./wolpd --version | sed -e 's! (git: .*!!')"

wolpd.init wolpd.service: Makefile
	sed -e 's![@]sbindir@!$(sbindir)!g' \
	    -e 's![@]sysconfdir@!$(sysconfdir)!g' \
	    -e 's![@]localstatedir@!$(localstatedir)!g' \
	  $(srcdir)/$@.in > $@

wolpd.init: wolpd.init.in
wolpd.service: wolpd.service.in

# Install
.PHONY: install-data-local
install-data-local: install-data-local-init \
		    install-data-local-sysconfig \
		    install-data-chroot-dir

.PHONY: install-data-local-init
install-data-local-init: wolpd.service wolpd.init
	@if systemctl --version >& /dev/null; \
	then \
	  unitpath="$$(systemctl show \
		       | grep '^UnitPath=' \
		       | sed -e 's!^UnitPath=!!' \
			     -e 's! !\n!g' \
		       | egrep -v '/(etc($$|/)|run/)')"; \
	  $(MKDIR_P) "$(DESTDIR)$$unitpath"; \
	  if [ -d "$$unitpath" ]; \
	  then \
	    (set -x; $(MKDIR_P) "$(DESTDIR)$$unitpath"); \
	    if [ -w "$(DESTDIR)$$unitpath" ]; \
	    then \
	      ( set -x; $(INSTALL_DATA) wolpd.service "$(DESTDIR)$$unitpath/wolpd.service" ); \
	    fi; \
	  fi; \
	else \
	  for d in /etc/init.d/rc.d /etc/init.d; \
	  do \
	    if [ -d "$$d" ]; \
	    then \
	      (set -x; $(MKDIR_P) "$(DESTDIR)$$d"); \
	      if [ -w "$(DESTDIR)$$d" ]; \
	      then \
		(set -x; $(INSTALL) wolpd.init "$(DESTDIR)$$d/wolpd.init" ); \
		exit $$?; \
	      fi; \
	    fi; \
	  done; \
	fi

.PHONY: install-data-local-sysconfig
install-data-local-sysconfig:
	$(MKDIR_P) "$(DESTDIR)$(sysconfdir)/sysconfig"
	$(INSTALL_DATA) $(srcdir)/wolpd.sysconfig "$(DESTDIR)$(sysconfdir)/sysconfig/wolpd"

.PHONY: install-data-chroot-dir
install-data-chroot-dir:
	$(MKDIR_P) "$(DESTDIR)$(localstatedir)/empty/wolpd"

# Uninstall
.PHONY: uninstall-local
uninstall-local: uninstall-local-init uninstall-local-sysconfig

.PHONY: uninstall-local-init
uninstall-local-init:
	@if systemctl --version >& /dev/null; \
	then \
	  unitpath="$$(systemctl show \
		       | grep '^UnitPath=' \
		       | sed -e 's!^UnitPath=!!' \
			     -e 's! !\n!g' \
		       | egrep -v '/(etc($$|/)|run/)')"; \
	  if [ -d "$$unitpath" -a -w "$(DESTDIR)$$unitpath" ]; \
	  then \
	    ( set -x; \
	      rm -f "$(DESTDIR)$$unitpath/wolpd.service" ); \
	  fi; \
	else \
	  for d in /etc/init.d/rc.d /etc/init.d; \
	  do \
	    if [ -d "$$d" -a -w "$(DESTDIR)$$d" ]; \
	    then \
	      (set -x; \
		rm -f "$(DESTDIR)$$d/wolpd.init" ); \
	      exit $$?; \
	    fi; \
	  done; \
	fi

.PHONY: uninstall-local-sysconfig
uninstall-local-sysconfig:
	rm -f "$(DESTDIR)$(sysconfdir)/sysconfig/wolpd"

# Clean & misc
CLEANFILES	     = $(expendable_generated_files)
MAINTAINERCLEANFILES = $(keep_generated_files)

@FI_AUTOMAKE@
