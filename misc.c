#include "fibc.h"

void
usage (char *name) {
	fprintf (stderr, " usage: %s -b -x -r -a -e -s -m -g -n -d -c -p -h\n\n", name);
	fprintf (stderr, " b: net scanner		optional\n");
	fprintf (stderr, " x: sniff password	optional\n");
	fprintf (stderr, " r: route IP		mandatory\n");
	fprintf (stderr, " a: read file		optional\n");
	fprintf (stderr, " e: send to remote peer	optional\n");
	fprintf (stderr, " s: spoofed source	optional\n");
	fprintf (stderr, " m: metric's value	default: 1\n");
	fprintf (stderr, " g: gateway IP		default: local machine\n");
	fprintf (stderr, " n: netmask		default: 255.255.255.0\n");
	fprintf (stderr, " d: daemonize		optional\n");
	fprintf (stderr, " c: check route		default: no\n");
	fprintf (stderr, " p: password		optional\n");
	fprintf (stderr, " N: ncurses mode        optional\n");
	fprintf (stderr, " h: this help\n\n");
	exit (1);
}

void
credits () {
	printf ("\n\n \e[0;31m\tRiPPeR v. 0.1.4\tby mydecay && click\e[0m\n\n");
}
