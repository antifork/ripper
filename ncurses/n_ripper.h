/*
    nast

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
#include "../fibc.h"

#define SAFE_WREFRESH(x)   do { wrefresh(x); } while(0)

#define SAFE_WIN_REFRESH(x)   do { wrefresh(x->win); } while(0)
#define SAFE_FREE(x) do{ if(x) { free(x); x = NULL; } }while(0)

#define SAFE_SCROLL_REFRESH(sx) do {  \
   pnoutrefresh(sx->win, sx->y_scroll, 0, sx->y + 1, sx->x + 1, sx->y + sx->lines - 2, sx->cols - 1 ); \
   wnoutrefresh(sx->out);              \
   doupdate();                         \
} while(0)

#define POLL_WGETCH(x, y)   do {    \
   struct pollfd poll_fd = {        \
      .fd = 0,                      \
      .events = POLLIN,             \
   };                               \
   poll(&poll_fd, 1, 1);            \
   if (poll_fd.revents & POLLIN)    \
      x = wgetch(y);                \
   else                             \
      usleep(1000);                 \
} while(0)

struct scrolling_window
{
   WINDOW *win;
   WINDOW *out;
   int y_scroll;
   int y_max;
   int lines;
   int cols;
   int x;
   int y;
   char *title;
};
typedef struct scrolling_window N_SCROLLWIN;

N_SCROLLWIN *newscrollwin(int lines, int cols, int y, int x, char *title, int maxlines);
void redrawscrollwin(N_SCROLLWIN *win, int focus);
void drawscroller(N_SCROLLWIN *win);
void winscroll(N_SCROLLWIN *win, int delta);
void delscrollwin(N_SCROLLWIN **win);

int routemake(void);
int n_main(void);
int print_stats(void);
int printing_commands(void);
int sniff_scan(void);

void nmenu(void);
int option_menu(void);
int inject_menu(void);
int help_menu(void);
void pop_up_win(void);
void init_scr(void);
void control_n(void);

/* insert functions */
int authors(void);

WINDOW *query;
WINDOW *werror;
N_SCROLLWIN *princ;
N_SCROLLWIN *winfo;
N_SCROLLWIN *wstream;
N_SCROLLWIN *wconn;

MENU *my_nmenu;
ITEM *curr_item;
WINDOW *my_nmenu_win;
WINDOW *pop_up;

int out;
