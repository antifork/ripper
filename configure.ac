################################################### 
#                                                 #
# ripper - RIPV2 Packet injection                 #
#	                                          #
# configure.ac - written by click@spine-group.org #
#                         mydecay@spine-group.org # 
#                                                 #
###################################################

AC_INIT(ripper,1.1-beta ,click@spine-group.org) 
AC_CONFIG_SRCDIR(main.c)
AC_CONFIG_HEADER(config.h)

# Print a banner
echo "
Please wait, I'm going to configure Ripper 
"

#########
# Subst #
#########

AC_SUBST(NCURSES)
AC_SUBST(GETOPT)


#################
# Checks for OS #
#################

AC_CANONICAL_TARGET
case "$target" in
*linux*)
	AC_MSG_NOTICE([Found Linux])
        ;;    
*freebsd*)
    	AC_MSG_WARN([
	FreeBSD port:we are working on...
	])
   	;;
*openbsd*)
	AC_MSG_NOTICE([Found OpenBSD])
  	;;
*netbsd*)
	AC_MSG_WARN([
	NetBSD port: we are working on...
	])
	;;
*)
        AC_MSG_WARN([

        Your OS seems to be officially unsupported yet, please send an email authors
	click@spine-group.org
	mydecay@spine-group.org
        ])
	;;
esac


################
# Setup prefix #
################

AC_PREFIX_DEFAULT(/usr/local)
if test "$prefix" = "NONE"; then
   prefix="/usr/local"
   fi
   

#######################
# Checks for compiler #
#######################

AC_PROG_CC


#########################
# Checks for libraries. #
#########################

#
# -- libnet --
#


filechk="yes"
AC_CHECK_FILE(/usr/lib/libnet.a,, filechk="no")
if test "$filechk" = "no"; then
 AC_CHECK_FILE(/usr/local/lib/libnet.a, filechk="yes" ; LDFLAGS="-L/usr/local/lib"; CPPFLAGS="-I/usr/local/include")
fi

if test "$filechk" = "no"; then AC_MSG_ERROR([

Libnet archive file (libnet.a) not found in /usr or /usr/local!

Libnet-1.1.x Packet Shaping Library is required.
You can download it from official web site: http://www.packetfactory.net/libnet

])
fi

AC_CHECK_LIB(net, libnet_name2addr4,, AC_MSG_ERROR([

Libnet-1.1.x Packet Shaping Library not found! It's required.
You can download it from official web site: http://www.packetfactory.net/libnet

]))

#
# -- libpcap --
#

filechk="yes"
AC_CHECK_FILE(/usr/lib/libpcap.a,, filechk="no")
if test "$filechk" = "no"; then
 AC_CHECK_FILE(/usr/local/lib/libpcap.a, filechk="yes" ; LDFLAGS="-L/usr/local/lib"; CPPFLAGS="-I/usr/local/include")
fi

if test "$filechk" = "no"; then AC_MSG_ERROR([

Libpcap archive file (libpcap.a) not found in /usr or /usr/local!

Libpcap-0.7.1 Packet Capture Library is required. 
You can download it from official web site: http://www.tcpdump.org/#current

])
fi

AC_CHECK_LIB(pcap, pcap_dispatch,, AC_MSG_ERROR([

Libpcap-0.7.1 Packet Capture Library not found! It's required. 
You can download it from official web site: http://www.tcpdump.org/#current

]))

############################
# Checks for linux pthread #
############################

case "$target" in
*linux*)
	AC_CHECK_LIB(pthread, pthread_create, , AC_MSG_ERROR([

	Linux threads library not found in your linux-box! Strange..

	]))
	
	CFLAGS="-Wall -O2 -D __Linux__"
	;;
*bsd*)
	CFLAGS="-Wall -O2 -D __OpenBSD__ -pthread"
	;;
esac	
##############################################
# Checks for headers and common libs/headers #
##############################################

AC_HEADER_STDC
AC_CHECK_HEADERS(errno.h sys/utsname.h,, AC_MSG_WARN(This headers are required!)) 

AH_TEMPLATE(HAVE_GETOPT, define if the getopt.h header is present, OpenBSD for ex. doesn't have one)
AC_CHECK_FUNC(getopt_long, AC_DEFINE(HAVE_GETOPT), GETOPT="getopt.o getopt1.o")
#AC_CHECK_HEADER(getopt.h, AC_DEFINE(HAVE_GETOPT), GETOPT="getopt.o getopt1.o")

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_MALLOC
AC_TYPE_SIGNAL
AC_FUNC_VPRINTF


##################
# Write Makefile #
##################

AC_OUTPUT(Makefile)


#################
# Print results #
#################

echo "
Ok. I have done with all. 

Results are:

PLATFORM ...... : `uname -mp`
O.S. .......... : `uname -rs` (`uname -n`)
COMPILER ...... : ${CC}
CFLAGS ........ : ${CFLAGS}
DEFINES ....... : -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H -DLIBNET_LIL_ENDIAN
CPPFLAGS ...... : ${CPPFLAGS}
LDFLAGS ....... : ${LDFLAGS}
LIBS .......... : ${LIBS}
PREFIX ........ : ${prefix}


Type 'make' to compile.
"

# ok we have done thx to embyte ;)