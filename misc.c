#include "fibc.h"

void
usage (char *name)
{
  fprintf (stderr, " Usage: %s -b -x -r [-a] [-s] -m -g -n [-d] -f -c\n\n",
	   name);
  fprintf (stderr, " b: net scanner\n");
  fprintf (stderr, " x: sniff password\n");
  fprintf (stderr, " r: route IP		mandatory\n");
  fprintf (stderr, " a: read file		optional\n");
  fprintf (stderr, " s: spoofed source	optional\n");
  fprintf (stderr, " m: metric's value	default: 1\n");
  fprintf (stderr, " g: gateway IP		default: local machine\n");
  fprintf (stderr, " n: netmask		default: 255.255.255.0\n");
  fprintf (stderr, " d: daemonize		optional\n");
  fprintf (stderr, " f: force		default: don't force\n");
  fprintf (stderr, " c: check route		default: no\n");
  fprintf (stderr, " h: this help\n\n");
  exit (1);
}

void
credits ()
{
  printf ("\n RiPPeR v.1.1-beta\tby mydecay && click\n\n");
}
