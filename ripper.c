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
	{'N', no_argument, "N/Nxarbngd", NULL, "ncurses mode"},
	{'x', no_argument, "x/xarbngd", "sniff", "sniff plain text password"},
	{'h', no_argument, NULL, NULL, "print help"},
	{'d', no_argument, "d/dc", NULL, "daemonize"},
	{'c', no_argument, "c/cd", NULL, "check injection"}, 
	{'+', 0, "|Narbx", 0, 0},
	{0, 0, 0, 0, 0}
};

int
main (int argc, char **argv) {
	unsigned long sp00f = 0, flags = 0;
	char ch, n_net[19];
	pthread_t pt[2];
	void (*main_func);
	void (*check_func)(void);
	struct net_param net;

	credits ();
	init_all (&net);
	if (argc < 2) usage(argv[0]);

	neo_getopt (argc, argv, opt, OPT_NOW);
	while ((ch = neo_getopt (argc, argv, opt, OPT_DELAYED)) != EOF) {
		switch (ch) {
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
				strncpy (net.password, neoptarg, 16);
				flags ^= PASS;
				break;
			case 'e':
				net.rip_group = inet_addr(neoptarg);
				break;
			case 'r':
				flags ^= INJECT;
				net.routes[ROUTE][0] = inet_addr (neoptarg);
				break;
			case 'm':
				net.routes[METRIC][0] = inet_addr (neoptarg);
				break;
			case 'g':
				net.routes[GW][0] = inet_addr (neoptarg);
				break;
			case 'n':
				net.routes[NETMASK][0] = inet_addr (neoptarg);
				break;
			case 'a':
				printf ("\tReading file %s...\n\n", neoptarg);
				rip_file_read (neoptarg, &net);
				flags ^= INJECT;
				break;
			case 'h':
				flags ^= N_MODE;
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
				graph = 1;
				/* MANTAINANCE MODE ON */
				printf("WARNING! New curses support is actually in maintenance mode! You cannot use it.\n\n");
				return ERR;
#else
				graph = 0;
				printf("You have not the ncurses support,if you want it\n");
				printf("you have to download the library and recompile RIPper\n");
				return ERR; 
#endif
				break;
		}
	}

	if(flags & N_MODE) 
		return main_graph(net);	

	if (flags & SCAN) {
		n_print ("princ", 1, 2, "\e[0;31m\tScanner Mode Enabled.\e[0m\n\n");
		n_print ("princ", 2, 2, "** press ^c to exit **\n\n");
		return scan_net (n_net);
	}
 
	if (flags & DAEMON) {
		if (fork ())
			exit (0);
	} else
		n_print ("princ", 1, 2, "\tPress 'q' and Enter to exit\n\n");

	if (flags & SPOOF)
		net.localaddr = sp00f;
 
	main_func = select_main(flags);

	if (pthread_create (pt, NULL, (void *)main_func, (void *)&net))
		fatal ("Cannot create pthread!\n\n");
	
	if (flags & CHECK) {
		check_func = select_check(flags);

		if (pthread_create(&pt[1], NULL, (void *)check_func, (void *)&net))
			fatal ("Cannot create pthread!\n\n");
	}

	// Infinite control loop 

	while ((char) getchar () != 'q');

	fprintf (stderr, "\nExiting...\n");
	pthread_cancel (pt[0]);
	pthread_join (pt[0], NULL);
	
	if (flags & CHECK) {
		pthread_cancel (pt[1]);
		pthread_join (pt[1], NULL);
	}
	
	return 0;
}
