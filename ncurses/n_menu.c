/*
    RIPper -RIPv2 Injection Tool-

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

*/

#include "n_ripper.h"
//#include "../fibc.h"
#include "../flags.h"

#define ROUTE "routes.conf"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define CTRLD 	4

char * in_ntoa (unsigned long in);

unsigned long sp00f;
char ch, subnet[18]; 
pthread_t pt, pt1;

int flagR = 0;

int sport,dport;
u_long ip_src, ip_dst;
libnet_t *L = NULL;

/*queste sono le scelte che verrano poi esposte all'avvio delle curser nei relativi menu e sotto menu*/
char *choices[] =
{
  " Main     ",
  " Inject   ",
  " Help     ",
  (char *)NULL,
};

char *option[] =
  {
    "Scan network          ",
    "Sniff password        ",
    "Wrote file            ",
    (char *)NULL,
  };

char *inject[] =
  {
    "Route IP               ",
    "Read file              ",
    "Send remote peer       ",
    "Spoofed source         ",
    "Metric value           ",
    "Gateway IP             ",
    "Netmask                ",
    "Check route            ",
    "Password               ",
    "Start injection        ",
(char*)NULL,
};

char *help[] =
  {
    "Commands               ",
    "Authors                ",
    (char *)NULL,
  };

void nmenu()
{
   ITEM **my_items;
   int ris;
   int n_choices, i;

   ris = 0;

	/* Create items */
   n_choices = ARRAY_SIZE(choices);//c'e' il define sopra della macro
   my_items = (ITEM **)calloc(n_choices, sizeof(ITEM *));//allochiamo gli oggetti
   for(i = 0; i < n_choices; ++i)//creiamo gli item
     my_items[i] = new_item(choices[i], choices[i]);//da capire meglio!!

	/* Crate menu */

   my_nmenu = new_menu((ITEM **)my_items);

	/* Set menu option not to show the description */
   menu_opts_off(my_nmenu, O_SHOWDESC);

	/* Create the window to be associated with the menu */
   my_nmenu_win = newwin(3,COLS, 3, 0);
   keypad(my_nmenu_win, TRUE);
   wbkgd(my_nmenu_win,COLOR_PAIR(3));

	/* Set main window and sub window */
   set_menu_win(my_nmenu, my_nmenu_win);
   set_menu_sub(my_nmenu, derwin(my_nmenu_win, 2, COLS-2, 1, 1));

	/* Set menu mark to the string " * " */
   set_menu_format(my_nmenu, 1, 3);
   set_menu_mark(my_nmenu, " ");
   //set_menu_mark(my_menu, " * ");

	/* Print a border around the main window and print a title */

   box(my_nmenu_win, 0, 0);
   
   mvwprintw(my_nmenu_win,1,COLS-10,"<- F1");

	/* Post the menu */

   post_menu(my_nmenu);
   wrefresh(my_nmenu_win);

}

int option_menu()
{
   ITEM **my_items;
   int c, ris;
   MENU *my_menu;
   WINDOW *my_menu_win;
   int n_choices, i;
  
   ris = 0;

	/* Create items */
   n_choices = ARRAY_SIZE(option);
   my_items = (ITEM **)calloc(n_choices, sizeof(ITEM *));
   for(i = 0; i < n_choices; ++i)
     my_items[i] = new_item(option[i], option[i]);

	/* Crate menu */

   my_menu = new_menu((ITEM **)my_items);

	/* Set menu option not to show the description */
   menu_opts_off(my_menu, O_SHOWDESC);

	/* Create the window to be associated with the menu */
   my_menu_win = newwin(5, 26, 5, 0);
   keypad(my_menu_win, TRUE);
   wbkgd(my_menu_win,COLOR_PAIR(3));

   set_menu_win(my_menu, my_menu_win);
   set_menu_sub(my_menu, derwin(my_menu_win, 4, 24, 1, 1));
   set_menu_mark(my_menu, " ");
   box(my_menu_win, 0, 0);

   post_menu(my_menu);
   wrefresh(my_menu_win);

   while( (c = wgetch(my_menu_win)) != 'q')
     {       
       switch(c)
	 {
	 case KEY_UP:
	   menu_driver(my_menu, REQ_UP_ITEM);
	   break;
	 case KEY_DOWN:
	   menu_driver(my_menu, REQ_DOWN_ITEM);
	   break;
	 case KEY_LEFT:
	   unpost_menu(my_menu);
	   free_menu(my_menu);
	   for(i = 0; i < n_choices; ++i)
	     free_item(my_items[i]);
	   werase(my_menu_win);
	   wrefresh(my_menu_win);
	   return(-2);
	   break;
	 case KEY_RIGHT:
	   unpost_menu(my_menu);
	   free_menu(my_menu);
	   for(i = 0; i < n_choices; ++i)
	     free_item(my_items[i]);
	   werase(my_menu_win);
	   wrefresh(my_menu_win);
	   return(-1);
	   break;
	 case 10:
	   curr_item = current_item(my_menu);
	   switch(item_index(curr_item))
	     {
	     case 0:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       pop_up_win();
	       mvwprintw(pop_up,2,2,"You must use the subnet/prefix format");
	       mvwprintw(pop_up,3,2,"Example 192.168.0.0/24");
	       wmove(pop_up,5,2);
	       echo();
	       wgetnstr(pop_up, n_net, 19);
	       noecho();
	       if (strcmp (subnet, "NULL")) /* != NULL */
		 {
		   flags ^= SCAN;
		   delwin(pop_up);
		   redrawscrollwin(princ,0);
		   werase(princ->win);
		   n_print("princ",1,2,"Scanner mode enabled");
                   n_print("winfo",1,2,"**Press q to shut down scan tread**");
		   if (pthread_create (&pt, NULL, (void *) scan_net, NULL))
		     n_print("winfo",4,2,"Cannot create pthread scan_net())");

		   while ((char) getch () != 'q');
		   
		   werase(princ->win);
		   n_print("princ",1,2,"Shut down net_scan thread");
		   pthread_cancel(pt);
		   pthread_join (pt, NULL);
		   werase(winfo->win);
		   n_print("winfo",1,2,"End of scan");
		   return 0;
		         
		 } 
	       else 	
		 {
		   delwin(pop_up);
		   redrawscrollwin(princ,0);
		 }      
	       return(0);
	       break;

	     case 1:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       pop_up_win();
	       mvwprintw(pop_up,2,2,"Do you want to sniff the auth pass (y/n)?");
	       wmove(pop_up,4,2);
	       do
		 {
		   ris=wgetch(pop_up);
		   if (ris == 'y')
		     {
		       flags ^= SNIFF;
		       sniff_scan();
		       n_print("princ",3,2,"End of passwd sniff");
		     }
		   else if (ris == 'n')
		     {
		       delwin(pop_up);
		       redrawscrollwin(princ,0);
		     }
		   
		 }
	       while( ris != 'y' && ris != 'n');
	       delwin(pop_up);
	       redrawscrollwin(princ,0);
	       return (0); 
	       break;
	       	       
	     case 2:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       pop_up_win();
	       routemake();
	       delwin(pop_up);
	       noecho();
	       redrawscrollwin(princ,0);
	       return(0);
	       break;
	     }
	   break;
	 }
       
       wrefresh(my_menu_win);
       
     }
   
   /* Unpost and free all the memory taken up */
   unpost_menu(my_menu);
   free_menu(my_menu);
   for(i = 0; i < n_choices; ++i)
     free_item(my_items[i]);
   werase(my_menu_win);
   wrefresh(my_menu_win);
   return (0);
}

int inject_menu()
{

   ITEM **my_items;
   int c,ris;
   MENU *my_menu;
   WINDOW *my_menu_win;
   int n_choices, i;
   char net_mask[16]="255.255.255.255";
   ris = 0;

	/* Create items */
   n_choices = ARRAY_SIZE(inject);
   my_items = (ITEM **)calloc(n_choices, sizeof(ITEM *));
   for(i = 0; i < n_choices; ++i)
     my_items[i] = new_item(inject[i], inject[i]);

	/* Crate menu */

   my_menu = new_menu((ITEM **)my_items);

	/* Set menu option not to show the description */
   menu_opts_off(my_menu, O_SHOWDESC);

	/* Create the window to be associated with the menu */
   my_menu_win = newwin(12, 27, 5, 11);
   keypad(my_menu_win, TRUE);
   wbkgd(my_menu_win,COLOR_PAIR(3));

   set_menu_win(my_menu, my_menu_win);
   set_menu_sub(my_menu, derwin(my_menu_win, 11, 25, 1, 1));
   set_menu_mark(my_menu, " ");
  box(my_menu_win, 0, 0);

   post_menu(my_menu);
   wrefresh(my_menu_win);

   while((c = wgetch(my_menu_win)) != 'q')
     {       
       switch(c)
       {
	case KEY_UP:
	  menu_driver(my_menu, REQ_UP_ITEM);
	  break;
	case KEY_DOWN:
	  menu_driver(my_menu, REQ_DOWN_ITEM);
	  break;
	case KEY_LEFT:
	  unpost_menu(my_menu);
	  free_menu(my_menu);
	  for(i = 0; i < n_choices; ++i)
	    free_item(my_items[i]);
	  werase(my_menu_win);
	  wrefresh(my_menu_win);
	  return(-2);
	  break;
	case KEY_RIGHT:
	  unpost_menu(my_menu);
	  free_menu(my_menu);
	  for(i = 0; i < n_choices; ++i)
	    free_item(my_items[i]);
	  werase(my_menu_win);
	  wrefresh(my_menu_win);
	  return(-1);
	  break;
	case 10:	/* Enter */
	curr_item = current_item(my_menu);
	  switch(item_index(curr_item))
	    {
	     case 0:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       pop_up_win();
	       mvwprintw(pop_up,2,2,"Insert the route IP to inject:");
	       wmove(pop_up,4,2);
	       echo();
	       wgetnstr(pop_up,n_route,16);
	       routes[0][0] = inet_addr(n_route);
	       flagR = 1;
	       noecho();
	       delwin(pop_up);
	       redrawscrollwin(princ,0);
	       if(!strncmp (net_mask,in_ntoa(routes[0][0]),16))
		 {
		   werase(winfo->win);
		   redrawscrollwin(winfo,0);
		   mvwprintw(winfo->win,2,2,"** Wrong IP route Address!! **");
		 }
	       return(0);
	       break;
	     
	     case 1:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       pop_up_win();
	       mvwprintw(pop_up,2,2,"Insert name file to inject multi routes");
	       mvwprintw(pop_up,3,2,"(NULL reads to routes.conf):");
	       wmove(pop_up,5,2);
	       echo();
	       wgetnstr(pop_up, routemake_file, 50);
	       noecho();
	       if (strcmp (routemake_file, "NULL")) /* != NULL */
		 {
		   delwin(pop_up);
		   redrawscrollwin(princ,0);
		   rip_file_read(routemake_file);
		 }
	       else 	
		 {		 
		   strcpy(routemake_file, "routes.conf");
		   delwin(pop_up);
		   redrawscrollwin(princ,0);
		   rip_file_read(routemake_file);
		 }
	       return(0);
	       break;

	     case 2:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]); 
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       pop_up_win();
	       mvwprintw(pop_up,2,2,"Insert the remote peer IP:");
	       wmove(pop_up,4,2);
	       echo();
	       wgetnstr(pop_up,rip_group,16);
	       noecho();
	       delwin(pop_up);
	       redrawscrollwin(princ,0);
	       return(0);
	       break;

	    case 3:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	        pop_up_win();
		mvwprintw(pop_up,2,2,"Insert the spoofed source IP:");
		wmove(pop_up,4,2);
		echo();
		wgetnstr(pop_up,n_spoof,16);
		sp00f = inet_addr(n_spoof);
		flags ^= SPOOF;
		localaddr = sp00f;
		noecho();
		delwin(pop_up);
		redrawscrollwin(princ,0);
		return (0);
	       break;

	    case 4:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       pop_up_win();
	       mvwprintw(pop_up,2,2,"Insert the metric value:");
	       wmove(pop_up,4,2);
	       echo();
	       wgetnstr(pop_up,n_metric,2);
	       routes[3][0] = inet_addr(n_metric);
	       noecho();
	       delwin(pop_up);
	       redrawscrollwin(princ,0);
	       return(0);
	      break;

	    case 5:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       pop_up_win();
	       mvwprintw(pop_up,2,2,"Insert the gateway IP:");
	       mvwprintw(pop_up,3,2,"NULL will set gateway to local machine");
	       wmove(pop_up,4,2);
	       echo();
	       wgetnstr(pop_up,n_gateway,16);
	       noecho();
	       if (strcmp (n_gateway, "NULL")) /* != NULL */
		 {
		   routes[2][0] = inet_addr (n_gateway);
		   delwin(pop_up);
		   redrawscrollwin(princ,0);
		 }
	       else 	
		 {		 
		   routes[2][0] = inet_addr("0.0.0.0");
		   delwin(pop_up);
		   redrawscrollwin(princ,0);
		 }
	       
	       return(0);
	       break;
	    
	    case 6:
	      unpost_menu(my_menu);
	      free_menu(my_menu);
	      for(i = 0; i < n_choices; ++i)
		free_item(my_items[i]);
	      werase(my_menu_win);
	      wrefresh(my_menu_win);
	      box(my_nmenu_win, 0, 0);
	      wrefresh(my_nmenu_win);
	      redrawscrollwin(princ,0);
	      refresh();
	      pop_up_win();
	      mvwprintw(pop_up,2,2,"Insert the netmask:");
	      mvwprintw(pop_up,3,2,"NULL will set netmask to 255.255.255.0");
	      wmove(pop_up,4,2);
	      echo();
	      wgetnstr(pop_up,n_netmask,16);
	      noecho();
	      if (strcmp (n_netmask, "NULL")) /* != NULL */
		{
		  routes[1][0] = inet_addr (n_netmask);
		  delwin(pop_up);
		  redrawscrollwin(princ,0);
		}
	      else
		{
		  routes[1][0] = inet_addr("255.255.255.0");
		  delwin(pop_up);
		  redrawscrollwin(princ,0);
		}
	      return(0);
	      break;
	      
     case 7:
       unpost_menu(my_menu);
       free_menu(my_menu);
       for(i = 0; i < n_choices; ++i)
	 free_item(my_items[i]);
       werase(my_menu_win);
       wrefresh(my_menu_win);
       box(my_nmenu_win, 0, 0);
       wrefresh(my_nmenu_win);
       redrawscrollwin(princ,0);
       refresh();
       pop_up_win();
       mvwprintw(pop_up,2,2,"do you want to check route? (y/n)");
       wmove(pop_up,4,2);
       do
	 {
	   ris=wgetch(pop_up);
	   if(ris == 'y')
	     { 
	       flags ^= CHECK;
	       delwin(pop_up);
	     }
	   else if(ris == 'n')
	     {
	       delwin(pop_up);
	       redrawscrollwin(princ,0);
	     }
	 }
       while ( ris != 'y' && ris != 'n');
       delwin(pop_up);
       redrawscrollwin(princ,0);
       return (0);
       break;
       
	case 8:
	  unpost_menu(my_menu);
	  free_menu(my_menu);
	  for(i = 0; i < n_choices; ++i)
	    free_item(my_items[i]);
	  werase(my_menu_win);
	  wrefresh(my_menu_win);
	  box(my_nmenu_win, 0, 0);
	  wrefresh(my_nmenu_win);
	  redrawscrollwin(princ,0);
	  refresh();
	  pop_up_win();
	  mvwprintw(pop_up,2,2,"Insert the password for autentication:");
	  wmove(pop_up,4,2);
	  echo();
	  wgetnstr(pop_up,password,16);
	  flags ^= PASS;
	  noecho();
	  delwin(pop_up);
	  redrawscrollwin(princ,0);
	  return(0);
	  break;
	 
       case 9:
	  unpost_menu(my_menu);
	  free_menu(my_menu);
	  for(i = 0; i < n_choices; ++i)
	    free_item(my_items[i]);
	  werase(my_menu_win);
	  wrefresh(my_menu_win);
	  box(my_nmenu_win, 0, 0);
	  wrefresh(my_nmenu_win);
	  redrawscrollwin(princ,0);
	  refresh();
	  pop_up_win();
	  
	  mvwprintw(pop_up,2,2,"Do you really want to start injection? (y/n)");
	  wmove(pop_up,4,2);
	  do
	    {
	      ris=wgetch(pop_up);
	      if(ris == 'y')
		{ 
		  delwin(pop_up);
		  redrawscrollwin(princ, 0);
		  n_main();
		}
	      else if(ris == 'n')
		{
		  delwin(pop_up);
		  redrawscrollwin(princ,0);
		}
	    }
	  while ( ris != 'y' && ris != 'n');
	  delwin(pop_up);
	  redrawscrollwin(princ,0);
	  return (0);
	  break;
	    }
	  break;
       }

       wrefresh(my_menu_win);
     }
   /* Unpost and free all the memory taken up */
   unpost_menu(my_menu);
   free_menu(my_menu);
   for(i = 0; i < n_choices; ++i)
     free_item(my_items[i]);
   werase(my_menu_win);
   wrefresh(my_menu_win);
   return(0);
}
     

int help_menu()
{
  ITEM **my_items;
  int c,ris;
  MENU *my_menu;
  WINDOW *my_menu_win;
  int n_choices, i;
  ris = 0;
  
  /* Create items */
  n_choices = ARRAY_SIZE(help);
  my_items = (ITEM **)calloc(n_choices, sizeof(ITEM *));
  for(i = 0; i < n_choices; ++i)
    my_items[i] = new_item(help[i], help[i]);
  
  /* Crate menu */
  
  my_menu = new_menu((ITEM **)my_items);
  
  /* Set menu option not to show the description */
  menu_opts_off(my_menu, O_SHOWDESC);
  
  /* Create the window to be associated with the menu */
  my_menu_win = newwin(4, 27, 5, 25);
  keypad(my_menu_win, TRUE);
  wbkgd(my_menu_win,COLOR_PAIR(3));
  
  set_menu_win(my_menu, my_menu_win);
  set_menu_sub(my_menu, derwin(my_menu_win, 3, 25, 1, 1));
  set_menu_mark(my_menu, " ");
  box(my_menu_win, 0, 0);
  
  post_menu(my_menu);
  wrefresh(my_menu_win);
  
  while((c = wgetch(my_menu_win)) != 'q')
    {       
      switch(c)
	{
	case KEY_UP:
	  menu_driver(my_menu, REQ_UP_ITEM);
	  break;
	case KEY_DOWN:
	  menu_driver(my_menu, REQ_DOWN_ITEM);
	  break;
	case KEY_LEFT:
	  unpost_menu(my_menu);
	  free_menu(my_menu);
	  for(i = 0; i < n_choices; ++i)
	    free_item(my_items[i]);
	  werase(my_menu_win);
	  wrefresh(my_menu_win);
	  return(-1);
	  break;
	case KEY_RIGHT:
	   unpost_menu(my_menu);
	   free_menu(my_menu);
	   for(i = 0; i < n_choices; ++i)
	     free_item(my_items[i]);
	   werase(my_menu_win);
	   wrefresh(my_menu_win);
	   return(-2);
	   break;
	 case 10:	/* Enter */
	   curr_item = current_item(my_menu);
	   switch(item_index(curr_item))
	     {
	     case 0:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       werase(winfo->win);
	       redrawscrollwin(winfo, 0);
	       printing_commands();
	       redrawscrollwin(winfo, 0);
	       return(0);
	       break;
	     case 1:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       werase(winfo->win);
	       redrawscrollwin(winfo, 0);
	       authors();
	       redrawscrollwin(winfo, 0);
	       return(0);
	     }
	  break;

	 }

	wrefresh(my_menu_win);
     }
     

 /* Unpost and free all the memory taken up */
  unpost_menu(my_menu);
  free_menu(my_menu);
  for(i = 0; i < n_choices; ++i)
    free_item(my_items[i]);
  werase(my_menu_win);
  wrefresh(my_menu_win);
  return(0);	
}

int n_main(void)
{
  if(!flagR)
    {
      werase(winfo->win);
      n_print("winfo",1,2,"If you want to inject you  have to enter the route IP !!");
      return (0);
    }
  n_print("winfo",2,2,"press q to shut down all threads");
  if (flags & SPOOF) 
    localaddr = sp00f;

  if (flags & PASS)
    {
      if (flags & CHECK) n_print ("princ",4,2,"Packet Injection Encrypted Mode With Checks Entered.");
      if (pthread_create (&pt, NULL, (void *) auth_pass, NULL))
	n_print("princ",1,2,"Cannot create pthread (auth_pass)");
    }

  else
    {
	if (flags & CHECK) n_print ("princ",8,2,"Packet Injection Mode With Checks Entered.");
	else n_print ("princ",8,2,"Packet Injection Mode Entered.");	
	if (pthread_create (&pt, NULL, (void *) send_fake_rip_response, NULL))
	  n_print("princ",3,2,"Cannot create pthread (send_fake_rip_response)");
    }
 if (flags & CHECK)
   {
     
     if (flags & PASS)
       {
	 if (pthread_create (&pt1, NULL, (void *) check_injection_crypt, NULL))
	   n_print("princ",4,2,"Cannot create pthread (check_injection_crypt)");
       }
     
     else
       {
	 if (pthread_create (&pt1, NULL, (void *) check_injection, NULL))
	   n_print("princ",5,2,"Cannot create pthread (check_injdection)");
       }
   }
 
 while ((char) getch () != 'q');

 werase(princ->win);
 n_print("princ",1,2,"Shut down al threads");
 pthread_cancel(pt);
 pthread_join (pt, NULL);
 if (flags & CHECK)
   {
     pthread_cancel (pt1);
     pthread_join (pt1, NULL);
   }
 return 0;
}
