#include "n_ripper.h"
#define ROUTECONF "routes.conf"

char * in_ntoa (unsigned long in);

int ng_print(char *wins, int y, int x, char *string)
{
	N_SCROLLWIN *w;
	w = NULL;

	if(!strcmp(wins, "princ"))
		w=princ;
	if(!strcmp(wins, "winfo"))
		w=winfo;
	if(!strcmp(wins, "pop")) {
		mvwprintw(pop_up, y, x, "%s", string);
		wrefresh(pop_up);
		return 0;
	}

	mvwprintw(w->win,y,x,"%s",string);
	SAFE_SCROLL_REFRESH(w);
	return 0;
}

void init_scr(void)
{
	werase(princ->win);
	werase(winfo->win);

	redrawscrollwin(princ, 0);
	redrawscrollwin(winfo, 0);
}

int
routemake (void)
{
	FILE *fd;
	char nroute[16];
	int i_nroute; 
	int i;
	char route[4][15];
  
	if ((fd = fopen (ROUTECONF, "w+")) < 0) {
		perror ("fopen()");
		exit (1);
	}
 
	mvwprintw(pop_up, 1, 2, "How many routes do you wanna inject? ");
	wmove(pop_up, 1, 40);
	echo();
	wgetnstr(pop_up,nroute, 16);
	i_nroute = atoi(nroute);
	if (i_nroute > 25) {
		n_print ("princ", 1, 2, "\nYou cannot inject more than 25 routes!!");
		refresh();
		delwin(pop_up);
		fclose(fd);
		return 0;
	}

	fprintf (fd, "%u\n", i_nroute);
	delwin(pop_up);
	for (i = 0; i < i_nroute; i++) {
		pop_up_win();
		mvwprintw(pop_up, 15, 4, "** Routes' File Genarator by mydecay && click **");
		mvwprintw (pop_up, 2, 2, "Route #%u", i + 1);
		mvwprintw (pop_up, 3, 2, "Route -> ");
		wmove(pop_up, 3, 10);
		wgetnstr(pop_up,route[0], 16);    
		mvwprintw (pop_up, 4, 2, "Netmask -> ");
		wmove(pop_up, 4, 12);
		wgetnstr (pop_up,route[1], 16);
		mvwprintw (pop_up, 5, 2, "Gateway -> ");
		wmove(pop_up, 5, 12);
		wgetnstr(pop_up,route[2], 16);
		mvwprintw (pop_up, 6, 2, "Metric -> ");
		wmove(pop_up, 6, 11);
		wgetnstr(pop_up,route[3], 16);
		refresh();
		fprintf (fd, "%u %u %u %u\n", inet_addr (route[0]),
					      inet_addr (route[1]), 
					      inet_addr (route[2]),
					      inet_addr (route[3]));
		delwin(pop_up);
	}

	fclose (fd);

	return 0;
}

int print_stats(unsigned long flags, struct net_param net)
{
	char *check = "no" ;
	char *sniff_pass = "no"; 
  
	if(flags & CHECK)
		check = "yes";
   
	if(flags & SNIFF)
		sniff_pass = "yes";

	pop_up_win();
	mvwprintw(pop_up, 3, 2, "**Actually you have set:**");
	mvwprintw(pop_up, 5, 2, "Route IP: %s", in_ntoa(net.routes[ROUTE][0]));
	mvwprintw(pop_up, 6, 2, "Send remote peer: %s", in_ntoa(net.rip_group));
	mvwprintw(pop_up, 7, 2, "Spoofed source: %s", in_ntoa(net.localaddr));
	mvwprintw(pop_up, 8, 2, "Metric value: %u", ntohl(net.routes[METRIC][0]));
	mvwprintw(pop_up, 9, 2, "Gateway IP: %s", in_ntoa(net.routes[GW][0]));
	mvwprintw(pop_up, 10, 2, "Nemask: %s", in_ntoa(net.routes[NETMASK][0]));
	mvwprintw(pop_up, 11, 2, "Check route: %s", check);
	mvwprintw(pop_up, 12, 2, "Sniff auth pass: %s",sniff_pass);
	mvwprintw(pop_up, 15, 17, "[*Press a key to exit*]");
	
	if(wgetch(pop_up)) {
		delwin(pop_up);
		redrawscrollwin(princ, 0);
	}
	
	return (0);
}

int sniff_scan(void)
{
	pthread_t pt;
	werase(winfo->win);
	n_print("winfo", 2, 2, "press q to shut down all threads");
	n_print ("princ", 6, 2, "Sniffer Password Mode Enabled.");
	if (pthread_create (&pt, NULL, (void *) sniff_passwd, &netz))
		n_print("princ", 2, 2, "Cannot create pthread (sniff_passwd)");
	while ((char) getch () != 'q');

	werase(princ->win);
	n_print("princ", 1, 2, "Shut down al threads");
	pthread_cancel(pt);
	pthread_join (pt, NULL);
	
	return (0);
}

int printing_commands(void)
{
	n_print("princ", 3, 2, "[F1] join the menu window");
	n_print("princ", 4, 2, "[F2] join the main window");
	n_print("princ", 5, 2, "[F3] join the help window"); 
	n_print("princ", 6, 2, "[m]  open Main menu");
	n_print("princ", 7, 2, "[i]  open Inject menu");
	n_print("princ", 8, 2, "[h]  open help menu");
	n_print("princ", 9, 2, "[q]  exit form a window or close RIPper");
	n_print("princ", 10, 2, "[x]  to erase the help window output");
	n_print("princ", 11, 2, "[d]  to erase the main window output");
	n_print("princ", 12, 2, "[a]  to print what you have actually set");

	return (0);
}

int authors(void)
{
	pop_up_win();
	mvwprintw(pop_up, 4, 14 ,"Michele 'mydecay' Marchetto");
	mvwprintw(pop_up, 5, 14, " <mydecay@spine-group.org>");
	mvwprintw(pop_up, 7, 14, "Valerio 'click' Genovese");
	mvwprintw(pop_up, 8, 14 ,"  <click@spine-group.org>");
	mvwprintw(pop_up, 15, 9, "Stay tuned on http://www.spine-group.org");
	if(wgetch(pop_up)) {
		delwin(pop_up);
		redrawscrollwin(princ, 0);
	}
	
	return (0);
}

void control_n(void) 
{
	int row, col;
	while(1) {
		getmaxyx(stdscr, row, col);
      
		if(row <= 30 || col < 85) {
			endwin();
			printf("\nSorry, you must have a screen of at least 85 colons and 30 rows\n\n");
			exit(1);
		}
	}
}
