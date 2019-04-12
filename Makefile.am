EXTRA_DIST = \
	wolpd.service \
	wolpd.spec \
	wolpd.sysconfig \
	wolpd.x

HELP2MAN = help2man

ACLOCAL_AMFLAGS = -I m4

sbin_PROGRAMS = wolpd
wolpd_SOURCES = wolpd.c

man8_MANS     = wolpd.8

generated_files = wolpd.8 wolpd.init

all-local: $(generated_files)

wolpd.8: wolpd
	$(HELP2MAN) -s 8 -N -I $(srcdir)/wolpd.x -o $@ ./wolpd

wolpd.init: Makefile
       sed -e 's![@]sbindir@!$(sbindir)!g' $(srcdir)/$@.in > $@

wolpd.init: wolpd.init.in


CLEANFILES = $(generated_files)
