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

void init_curs(void);
void title(void);
int get_info(void);

int main_graph(void)
{
   int row,col;
   int key, c;
   int ris;
   int l;

   key = c = 0xff;/*unuse value*/
   ris = 0;
   l = 3;
   
   init_curs();
   getmaxyx(stdscr,row,col);
   if(row<24 || col<78)
     {
	endwin();
	printf("\nSorry,you must have a screen of at least 85 colons and 31 rows\n\n");
	exit(1);
     }

   if (princ == NULL)
     {

	princ = newscrollwin(LINES-13, COLS, 6, 0, " Main Window    <- F2", 1000);
	SAFE_SCROLL_REFRESH(princ);
     }
   if (winfo == NULL)
     {

	winfo = newscrollwin(7, COLS, LINES-7, 0,  " Help Window    <- F3", 300);
	SAFE_SCROLL_REFRESH(winfo);
     }

   winscroll(princ, -1000);  
   winscroll(winfo,-300);  

   redrawscrollwin(princ, 0);    
   redrawscrollwin(winfo, 0);

   refresh();

   title(); 

   nmenu(); 

   do
     {

	redrawscrollwin(princ, 0);
	redrawscrollwin(winfo, 0);

	key=getch();

	switch(key)
	  {
	   case KEY_F(1):
	     while( (out!=1) && ((c = wgetch(my_nmenu_win)) != 'q') )
	       {
		  switch(c)
		    {
		     case KEY_LEFT:
		       menu_driver(my_nmenu, REQ_PREV_ITEM);
		       break;
		     case KEY_RIGHT: 
		       menu_driver(my_nmenu, REQ_NEXT_ITEM);
		       break;
		     case 10:
		       curr_item = current_item(my_nmenu);
		       switch(item_index(curr_item))
			 {
			  case 0:
			 option:
			    box(my_nmenu_win, 0, 0);			    
			    wrefresh(my_nmenu_win);
			    redrawscrollwin(princ, 0);
			    ris = option_menu();
			    if (ris == -1)
			      {
				 menu_driver(my_nmenu, REQ_RIGHT_ITEM);
				 goto inject;
			      }
			    if (ris == -2)
			      {
				 menu_driver(my_nmenu, REQ_LAST_ITEM);
				 goto help;
			      }
			    if(ris == 0)
			      {
				 (out=1);
				 menu_driver(my_nmenu, REQ_FIRST_ITEM);
			      }

			    break;
			  case 1:
			    inject:
			    box(my_nmenu_win, 0, 0);
			    wrefresh(my_nmenu_win);
			    redrawscrollwin(princ, 0);
			    ris = inject_menu();
			    if (ris == -1)
			      {
				 menu_driver(my_nmenu, REQ_RIGHT_ITEM);
				 goto help;
			      }
			    if (ris == -2)
			      {
				 menu_driver(my_nmenu, REQ_LEFT_ITEM);
				 goto option;
			      }

			    if(ris == 0)
			      {
				 (out=1);
				 menu_driver(my_nmenu, REQ_FIRST_ITEM);
			      }

			    break;
			 case 2:
			 help:
			   box(my_nmenu_win, 0, 0);
			   wrefresh(my_nmenu_win);
			   redrawscrollwin(princ,0);
			   ris = help_menu();
			   if (ris == -1)
			     {
			       menu_driver(my_nmenu, REQ_LEFT_ITEM);
			       goto inject;
			     }
			   if (ris == -2)
			     {
			       menu_driver(my_nmenu, REQ_FIRST_ITEM);
			       goto option;
			     }
			   if (ris == 0)
			     {
			       (out=1);
			       menu_driver(my_nmenu, REQ_FIRST_ITEM);
			     }
			   break;
			 }
		       box(my_nmenu_win, 0, 0);        
		       wrefresh(my_nmenu_win);         
		       pos_menu_cursor(my_nmenu);      
		       redrawscrollwin(princ, 0);      
		       break;
		    }

	       }
	     out=0;
	     break;

	   case KEY_F(2):
	     while((c = getch()) != 'q')
	       {
		  switch(c)
		    {
		     case KEY_UP:
		       winscroll(princ, -1);
		       break;
		     case KEY_DOWN:
		       winscroll(princ, +1);  
		       break;
		     case KEY_NPAGE:
		       winscroll(princ, +10);  
		       break;
		     case KEY_PPAGE:
		       winscroll(princ, -10);  
		       break;
		    }
		  redrawscrollwin(princ, 0);
	       }
	     break;

	   case KEY_F(3):
	     while((c = getch()) != 'q')
	       {
		  switch(c)
		    {
		     case KEY_UP:
		       winscroll(winfo, -1);  
		       break;
		     case KEY_DOWN:
		       winscroll(winfo, +1);  
		       break;
		     case KEY_NPAGE:
		       winscroll(winfo, +5);  
		       break;
		     case KEY_PPAGE:
		       winscroll(winfo, -5);  
		       break;
		    }
		  redrawscrollwin(winfo, 0);
	       }
	     break;

	   case 'h':
	     menu_driver(my_nmenu, REQ_LAST_ITEM);
	     goto help;
	     break;
	   case 'm':
	     menu_driver(my_nmenu, REQ_FIRST_ITEM);
	     goto option;
	     break;
	   case 'i':
	     menu_driver(my_nmenu, REQ_NEXT_ITEM);
	     goto inject;
	     break;
	   case 'd':
	     werase(winfo->win);
	     redrawscrollwin(winfo,0);
	     break;
	   case 'x':
	     werase(princ->win);
	     redrawscrollwin(princ,0);
	     break;
	  case 'a':
	    print_stats();
	    break;
	   case 'q':
	     pop_up_win();
	     mvwprintw(pop_up,7,10,"Are you sure you want to exit (y/n)?");
	     wmove(pop_up,4,2);
	     do
	       {
		  ris=wgetch(pop_up);
		  if (ris == 'y')
		    {
		       endwin();
		       fatal("\nRIPper is gona down...\n\n");
		       exit(0);
		    }

		  else if (ris == 'n');
	       }
	     while( ris != 'y' && ris != 'n');
	     delwin(pop_up);
	     redrawscrollwin(princ,0);
	     break;
	  }
     }
   while (key!='X');
   endwin();
   printf("\nRIPper is gona down\n\n");
   return 0;
}

void init_curs(void)
{

		/* Initialize curses */
   initscr();

   start_color();
   cbreak();
   noecho();
   keypad(stdscr, TRUE);

   curs_set(0);
   init_pair(1, COLOR_BLACK, COLOR_RED);
   init_pair(2, COLOR_CYAN, COLOR_BLACK);
   init_pair(3, COLOR_RED, COLOR_BLACK);
   init_pair(4, COLOR_WHITE, COLOR_BLACK);

}

void title(void)
{

   char TITLE[30];
   WINDOW *title;
   sprintf(TITLE,"RIPper - RIPV2 INJECTION TOOL  -");
   title = subwin(stdscr,3,COLS,0,0);
   wbkgd(title,COLOR_PAIR(1));
   box(title,0,0);
   mvwprintw(title,1,(COLS -strlen(TITLE))/2, TITLE);
   wrefresh(title);
}

void pop_up_win(void)
{
   char message[23];
   sprintf(message,"RIPper injection tool");
   pop_up = newwin(17,55,(LINES-17)/2,(COLS-55)/2);
   wbkgd(pop_up,COLOR_PAIR(4));
   box(pop_up,0,0);
   mvwprintw(pop_up,0,(55 -strlen(message))/2, message);
   wrefresh(pop_up);
}
