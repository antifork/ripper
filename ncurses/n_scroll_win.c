#include "n_ripper.h"

N_SCROLLWIN *newscrollwin(int lines, int cols, int y, int x, char *title, int maxlines)
{
	N_SCROLLWIN *win;

	win = calloc(1, sizeof(N_SCROLLWIN));

	win->win = newpad(maxlines, cols - 2);
	win->out = newwin(lines, cols, y, x);
	win->y_max = maxlines;
	win->lines = lines;
	win->cols = cols;
	win->x = x;
	win->y = y;
	win->title = strdup(title);

	scrollok(win->win, TRUE);

	/* move the cursor to the right starting point */
	win->y_scroll = maxlines - (lines-2);
	wmove(win->win, win->y_scroll - 1, 0);

	/* draw the outer window */
	wattrset(win->out, COLOR_PAIR(5));

	wborder(win->out, ACS_VLINE, ACS_VLINE, ACS_HLINE, ACS_HLINE,
			  ACS_ULCORNER, ACS_URCORNER,
			  ACS_LLCORNER, ACS_LRCORNER);

	wmove(win->out, 0, 2);
	wattrset(win->out, COLOR_PAIR(5));
	waddstr(win->out, " ");
	waddstr(win->out, title);
	waddstr(win->out, " ");
	wattrset(win->out, COLOR_PAIR(5));

	drawscroller(win);

	return win;
}

/* redraw the window with or without focus */

void redrawscrollwin(N_SCROLLWIN *win, int focus)
{
	if (focus)
		wattron(win->out, A_BOLD);

	werase(win->out);
	wmove(win->out, 0, 0);

	wattron(win->out, COLOR_PAIR(3));

	wborder(win->out, ACS_VLINE, ACS_VLINE, ACS_HLINE, ACS_HLINE,
			  ACS_ULCORNER, ACS_URCORNER,
			  ACS_LLCORNER, ACS_LRCORNER);

	if (focus) {
		wmove(win->out, 0, 0);
		wattron(win->out, COLOR_PAIR(5));
		waddch(win->out, ACS_LARROW);
		waddch(win->out, ACS_RARROW);
		wattroff(win->out, COLOR_PAIR(5));
	}

	wattron(win->out, COLOR_PAIR(2));
	wmove(win->out, 0, 2);
	waddstr(win->out, " ");
	waddstr(win->out, win->title);
	waddstr(win->out, " ");
	wattroff(win->out, COLOR_PAIR(2));

	redrawwin(win->out);

	if (focus)
		wattroff(win->out, A_BOLD);

	drawscroller(win);

	SAFE_SCROLL_REFRESH(win);
}

/* display the scroll indicator on the right */

void drawscroller(N_SCROLLWIN *win)
{
	short height = (win->lines-2) * (win->lines-2) / win->y_max;
	short vpos = win->lines * win->y_scroll / win->y_max;

	wattron(win->out, COLOR_PAIR(2));
	wattroff(win->out, A_BOLD);

	height = (height < 1) ? 1 : height;

	vpos = (vpos == 0) ? 1 : vpos;
	vpos = (vpos > (win->lines-1) - height) ? (win->lines-1) - height : vpos;

	wmove(win->out, 1, win->x + win->cols - 1);
	wvline(win->out, ACS_CKBOARD, win->lines - 2);
	wattron(win->out, A_REVERSE);
	wmove(win->out, vpos, win->x + win->cols - 1);
	wvline(win->out, ' ', height);
	wattroff(win->out, A_REVERSE);

	wnoutrefresh(win->out);
}

/* scroll a window for delta lines */

void winscroll(N_SCROLLWIN *win, int delta)
{
	win->y_scroll += delta;
	win->y_scroll = (win->y_scroll < 0) ? 0 : win->y_scroll;
			 win->y_scroll = (win->y_scroll > win->y_max - (win->lines-2) )
			 ? win->y_max - (win->lines-2)
			 : win->y_scroll;

	drawscroller(win);
	SAFE_SCROLL_REFRESH(win);
}

void delscrollwin(N_SCROLLWIN **win)
{
	werase((*win)->win);
	SAFE_WREFRESH((*win)->win);
	werase((*win)->out);
	SAFE_WREFRESH((*win)->out);
	delwin((*win)->win);
	delwin((*win)->out);
	SAFE_FREE((*win)->title);
	SAFE_FREE(*win);
}
