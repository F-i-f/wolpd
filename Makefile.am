EXTRA_DIST = \
	wolpd.init.in \
	wolpd.service.in \
	wolpd.spec \
	wolpd.sysconfig \
	wolpd.x

HELP2MAN = help2man

ACLOCAL_AMFLAGS = -I m4

sbin_PROGRAMS = wolpd
wolpd_SOURCES = wolpd.c

man8_MANS     = wolpd.8

generated_files = wolpd.8 wolpd.init wolpd.service

all-local: $(generated_files)

wolpd.8: wolpd
	$(HELP2MAN) -s 8 -N -I $(srcdir)/wolpd.x -o $@ ./wolpd

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
CLEANFILES = $(generated_files)

.PHONY: all-local install-local install-local-init install-local-sysconfig
.PHONY: uninstall-local uninstall-local-init uninstall-local-sysconfig
