CC          = gcc
CFLAGS      = -Wall -O2  
CPPFLAGS    =    
LDFLAGS     = 
LIBS        = -lpcap -lnet -lpthread   
#DEFS        = -DHAVE_NET_ETHERNET_H -DLIBNET_LIL_ENDIAN
DEFS	    = `libnet-config --defines`
INSTALL     = @INSTALL@

prefix      = /usr
exec_prefix = ${prefix}
bindir      = ${exec_prefix}/bin
mandir      = ${prefix}/man
datadir     = ${prefix}/share
srcdir      = .
shtool      = @SHTOOL@

OBJS = main.o ripper.o misc.o neo_options.o

all:	routemake ripper
	
ripper:	$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o ripper $(OBJS) $(LIBS) 
	@echo
	@echo "Successful! Now type make install"
	@echo

routemake: 
	$(CC) routemake.c -o routemake

.c.o:
	$(CC) $(CFLAGS) $(DEFS) $(CPPFLAGS) -c $< -o $@

install:
	chown root ripper ripper.8
	cp -fR ripper ${exec_prefix}/bin
	cp -fR ripper.8 ${prefix}/man/man8
	@echo
	@echo "Enjoy RiPPeR - mydecay && click"
	@echo

clean:
	rm -fR *~ *.bak *.o *.cache *.log ripper config.status config.h stamp-h* routemake

distclean: clean
	rm -f ${exec_prefix}/bin/ripper ${prefix}/man/man8/ripper.8
