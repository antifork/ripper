/* $Id$
*/
/*
 * neo_getopt(): an advanced version derived by original libc getopt.
 *
 * Copyright (c) 2002 Bonelli Nicola <bonelli@antifork.org>
 *
 * All rights reserved.
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. 2.
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

static const char cvsid[] = "$Id$";
static const char copyright[] = "Copyright (c) 2002 Bonelli Nicola <bonelli@antifork.org>";

extern char *__progname;

int neoverbose;                  /* control the otuput fashoin:0 = classic, 1 = verbose */

#define   NEO_LIBRARY
#include "neo_getopt.h"
#define RSIZE	(112 bit)	// from 21 (!) .. up to 127

static void fatal(char *pattern,...) __attribute__((noreturn));
static void
fatal(char *pattern,...)
{
	va_list ap;
	va_start(ap, pattern);
	vfprintf(stderr, pattern, ap);
	va_end(ap);
	exit(1);
}

static int
warn(char *pattern,...)
{
	static int n = 0;
	int tmp;
	va_list ap;

	if (pattern == NULL) {	/* reset */
		tmp = n, n = 0;
		return (tmp);
	}
	n++;
	va_start(ap, pattern);
	vfprintf(stderr, pattern, ap);
	va_end(ap);
	return (n);
}

static int
check_optmask(char c, char *s)
{
	REG reg[RSIZE], r[RSIZE], m[RSIZE];
	int sep = 0, type = 0, i;

	REG_CLR(r, RSIZE);
	REG_CLR(m, RSIZE);

	if (s == NULL)
		return 0;

	for (i = 0; s[i] != 0; i++) {
		switch (s[i]) {
		case '|':
			type = OR_MASK;
			if (c != '+')
				warn("\n[+] %s: -%c opt \"%s\" mask error. wrong separator (and-mask format is \"x/xy\")",
				     __FUNCTION__, c, s);	/* error */
			if (sep != 0)
				warn("\n[+] %s: -%c opt \"%s\" mask parse error.", __FUNCTION__, c, s);	/* error */
			sep++;
			continue;
		case '/':
			type = AND_MASK;
			if (c == '+')
				warn("\n[+] %s: -%c opt \"%s\" mask error. wrong separator (or-mask format is \"x|yz\")",
				     __FUNCTION__, c, s);	/* error */
			if (sep != 0)
				warn("\n[+] %s: -%c opt \"%s\" mask parse error.", __FUNCTION__, c, s);	/* error */
			sep++;
			continue;
		default:
			REG_BS((sep == 0 ? r : m), (s[i] - '!'));
		}
	}

	/* mask integrity check */

	if (type == AND_MASK) {
		REG_CPY(m, reg, RSIZE);
		REG_AND(r, reg, RSIZE);
		if (!REG_CMP(r, reg, RSIZE))
			warn("\n[+] %s: -%c opt \"%s\" mask error. bogus and-mask", 
				__FUNCTION__, c, s);	/* error */
	}
	if (type == OR_MASK && !REG_ISNULL(r, RSIZE)) {
		REG_CPY(m, reg, RSIZE);
		REG_AND(r, reg, RSIZE);
		if (REG_CMP(r, reg, RSIZE))
			warn("\n[+] %s: -%c opt \"%s\" mask error. bogus or-mask", 
				__FUNCTION__, c, s);	/* error */
	}
	return (0);
}

static int
check_options(const struct neo_options * n)
{
	REG reg[RSIZE];
	int gerr = 0, err = 0;

	REG_CLR(reg, RSIZE);
	warn(NULL);		/* reset */

	for (; n->opt != 0; n++) {
		if (neoverbose)
			printf("    %s: check (%c) -> \"%s\" option... ", 
				__FUNCTION__, n->opt, n->mask), fflush(stdout);
		switch (n->opt) {
		case '!':
		case '-':
			break;
		case '+':
			check_optmask(n->opt, n->mask);
			break;
		default:
			if (REG_BT(reg, (n->opt - '!')))
				warn("\n[+] %s: -%c opt error. option already in use", 
					__FUNCTION__, n->opt);
			REG_BS(reg, (n->opt - '!'));
			check_optmask(n->opt, n->mask);
		}
		err = warn(NULL);
		gerr += err;

		if (neoverbose)
			printf(err ? "\n" : "ok\n");
	}

	if (gerr != 0)
		fatal("\n[+] %s: %d %s encontered. exit forced.\n", 
			__FUNCTION__, gerr, (gerr == 1 ? "error" : "errors"));

	return (0);
}

static int
compile_optmask(char c, char *s, REG r[], REG m[])
{
	int ret = 0, sep = 0, type = 0, i;

	REG_CLR(r, RSIZE);
	REG_CLR(m, RSIZE);

	if (s == NULL)
		return 0;

	for (i = 0; s[i] != 0; i++) {
		switch (s[i]) {
		case '|':
			type = OR_MASK;
			sep++;
			continue;
		case '/':
			type = AND_MASK;
			sep++;
			continue;
		default:
			REG_BS((sep == 0 ? r : m), (s[i] - '!'));
			ret |= (sep == 0 ? 2 : 1);
		}
	}
	return (ret);
}


static char *
compile_optstring(const struct neo_options * n)
{
	const struct neo_options *m;
	char *op;
	int l = 0;

	for (m = n; m->opt != 0; m++)
		l += (m->has_arg > 1 ? 2 : 1);
	op = (char *) malloc(l + 1);
	op[l] = 0;
	for (m = n, l = 0; m->opt != 0; m++)
		switch (m->has_arg) {
		case 0:
			continue;
		case 1:
			op[l++] = m->opt;
			continue;
		default:
			op[l++] = m->opt;
			op[l++] = ':';
		}
	return (op);
}


static char spaces[32] = {[0 ... 31] = ' '};

/***
 *** public functions
 ***/

int
neo_usage(FILE * f, char *h, const struct neo_options * n)
{
	int br = 1;

	if (n == NULL)
		fatal("[+] %s: struct neo_options is a NULL pointer?\n", __FUNCTION__);

	/* print header */

	if (h != NULL)
		fprintf(f, "%s\n", h);
	else
		fprintf(f, "usage: %s [OPTIONS]\n", __progname);

	for (; n->opt != 0; n++)
		switch (n->opt) {
		case '-':
			fprintf(f, " %s\n", n->usage);
			continue;
		case '+':
			continue;
		default:
			if (n->usage != NULL) {
				if (n->arg == NULL) {
					fprintf(f, "   -%c                           %s\n", n->opt, n->usage);
					break;
				}
				spaces[(sizeof(spaces) - br) & 0x1f] = ' ';
				fprintf(f, "   -%c %s%n", n->opt, n->arg, &br);
				spaces[(sizeof(spaces) - br) & 0x1f] = '\0';
				fprintf(f, "%s%s\n", spaces, n->usage);
			}
		}
	return (0);
}

int
neo_showdepend(FILE * f, const struct neo_options * n)
{

	if (n == NULL)
		fatal("[+] %s: struct neo_options is a NULL pointer?\n", __FUNCTION__);

	fprintf(f, "%s options dependencies:\n", __progname);
	for (; n->opt != 0; n++)
		switch (n->opt) {
		case '-':
		case '!':
			continue;
		case '+':
			if (n->mask != NULL)
				fprintf(f, "      (or)                      \"%s\"\n", n->mask);
			continue;
		default:
			if (n->mask != NULL)
				fprintf(f, "   -%c (and)                     \"%s\"\n", n->opt, n->mask);
		}
	return (0);
}


/*
 * Copyright (c) 1987, 1993, 1994
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

int neopterr = 1,		/* if error message should be printed */
    neoptind = 1,		/* index into parent argv vector */
    neoptopt,			/* character checked for validity */
    neoptreset;			/* reset neo_getopt */
char *neoptarg;			/* argument associated with option */


#define BADCH        (int)'?'
#define BADARG        (int)':'
#define EMSG        ""

#define return_w(x)  do { ret=x; goto ret_control; } while (0)

static char *rcsid __attribute__((unused)) = "$OpenBSD: getopt.c,v 1.4 2002/12/08 22:57:14 millert Exp $";

int
neo_getopt(int nargc, char *const nargv[], const struct neo_options * n, int mode)
{
	REG opts[RSIZE], mask[RSIZE], temp[RSIZE];
	static REG master[RSIZE];
	static char *ostr;
	static char *place = EMSG;
	char *oli;
	int c, ret;

	if (ostr == NULL) {
		/* init */
		check_options(n);
		ostr = compile_optstring(n);
	}
restart:
	if (neoptreset || !*place) {	/* update scanning pointer */
		neoptreset = 0;
		if (neoptind >= nargc || *(place = nargv[neoptind]) != '-') {
			place = EMSG;
			return_w(-1);
		}
		if (place[1] && *++place == '-') {	/* found "--" */
			++neoptind;
			place = EMSG;
			return_w(-1);
		}
	}

	if ((neoptopt = (int) *place++) == (int) ':' ||
	    !(oli = strchr(ostr, neoptopt))) {
		/*
                 * if the user didn't specify '-' as an option,
                 * assume it means -1.
                 */
		if (neoptopt == (int) '-')
			return_w(-1);
		if (!*place)
			++neoptind;
		if (neopterr && *ostr != ':')
			(strchr(ostr,'?') ? warn("[!] %s: illegal option -- %c\n", __FUNCTION__, neoptopt) : 
						fatal("[!] %s: illegal option -- %c\n", __FUNCTION__, neoptopt));
				
		return_w(BADCH);
	}
	if (*++oli != ':') {	/* don't need argument */
		neoptarg = NULL;
		if (!*place)
			++neoptind;
	} else {		/* need an argument */
		if (*place)	/* no white space */
			neoptarg = place;
		else if (nargc <= ++neoptind) {	/* no arg */
			place = EMSG;
			if (*ostr == ':')
				return_w(BADARG);
			if (neopterr)
				fatal("[!] %s: option requires an argument -- %c\n", 
					__FUNCTION__, neoptopt);

			return_w(BADCH);
		} else		/* white space */
			neoptarg = nargv[neoptind];
		place = EMSG;
		++neoptind;
	}

	REG_BS(master, (neoptopt - '!'));
	return_w(neoptopt);	/* dump back option letter */

/* <--- end of Copyright (c) 1987, 1993, 1994 The Regents of the University of California. ---> */

ret_control:
	switch (mode) {
	case OPT_NOW:
		if (ret == 'h') {
			neoptreset = 1;
			neoptind = 1;
			return (ret);	/* exit forced */
		}
		if (ret != -1)
			goto restart;
		else {
			neoptreset = 1;
			neoptind = 1;
		}
		break;
	case OPT_DELAYED:
		if (ret != -1)
			return (ret);
		break;
	default:
		fatal("[+] %s: unknown mode=%d\n", __FUNCTION__, mode);
	}

	for (; n->opt != 0; n++) {
		switch (n->opt) {
			/* comment line */
		case '-':
			continue;
			/* obligation line */
		case '+':
			REG_CPY(master, temp, RSIZE);
			c = compile_optmask(n->opt, n->mask, opts, mask);

			if ( c == 0 || c == 2 )	 /* NULL/NULL || OK/NULL */
				continue;
			
			/* OK/OK : control whether to check the (or) mask or not */
			if ( c == 3 ) {
                        REG_AND(temp, opts, RSIZE);
                        if (REG_ISNULL(opts, RSIZE))
                        	continue;
			}

			/* c=1;  NULL/OK */		
			/* obligation(or) mask check */

			REG_AND(mask, temp, RSIZE);
			if (REG_ISNULL(temp, RSIZE))
				fatal("[!] %s: or-mask \"%s\" error. (missing options?)\n",
				      __FUNCTION__, n->mask);
			continue;
			/* (and) mask check */
		default:
			if (REG_BT(master, (n->opt - '!')) == 0)
				continue;	/* the current options wasn't
						 * set, its optmask is
						 * ignored */

			/* be sure that the current options is set */
			REG_CPY(master, temp, RSIZE);
			REG_BS(temp, (n->opt - '!'));
			compile_optmask(n->opt, n->mask, opts, mask);
			REG_AND(mask, temp, RSIZE);

			if (!REG_CMP(temp, opts, RSIZE))	/* error */
				fatal("[!] %s: -%c and-mask \"%s\" error. (mismatch dependency?)\n",
				      __FUNCTION__, n->opt, n->mask);
			continue;
		}

	}
	return (ret);
}


#ifdef TEST

struct neo_options opt[] = {
	{'-', 0, 0, NULL, "first section"},
	{'a', no_argument, "a/ab", NULL, "test"},
// 	{'a', no_argument, "a/ab", NULL, "test"}, //<--a is already in use.
// 	{'m', no_argument, "a/cb", NULL, "test"}, //<-bugus and - mask(never true)
// 	{'k', no_argument, "a|cb", NULL, "test"}, //<-wrong separator:and - mask format is "a/ab"
	{'b', no_argument, "bc/bc", NULL, "test.."},
	{'-', 0, 0, NULL, "second section"},
	{'c', required_argument, "cd/cd", "int", "test..."},
	{'d', required_argument, "d/d", "u_int", "test...."},
// 	{'l', no_argument, "a/sd/d", NULL, "---"}, //<-parse error
	{'e', no_argument, "", NULL, "---"},
	{'z', no_argument, "", NULL, "test....."},
	{'h', no_argument, "", NULL, "print help"},
	{'!', no_argument, NULL, NULL, "show dependencies"},
//	{'?', no_argument, NULL, NULL, 0},
	{'+', 0, "az|de", 0, 0},
//	{'+', 0, "a|ade", 0, 0}, //<-bogus or - mask(always true)
//	{'+', 0, "a/bc", 0, 0}, //<-wrong separator:or - mask format is "x|yz"
	{'+', 0, "|dz", 0, 0},
	{0, 0, 0, 0, 0}
};



int
main(int argc, char **argv)
{
	int i;

//	extern int neopterr;               	/* if error message should be printed */
//	extern int neoptind;               	/* index into parent argv vector */
//	extern int neoptopt;                   	/* character checked for validity */
//	extern int neoptreset;                 	/* reset neo_getopt */
//	extern char *neoptarg;                 	/* argument associated with option */
//	extern int neoverbose;			/* control the output fashion: 0=normal, 1=verbose */
//
//      int
//      neo_getopt(int argc, char **argv, struct neo_options array[], int MODE);
//      
//      argc, argv: number and command line arguments passed to main.
//      struct neo_options array[]: array of config structure.
//
//      MODE: can be either OPT_NOW or OPT_DELAYED.  
//
//           *OPT_NOW    : check all options given in a single step.
//            OPT_DELAYED: check a single option per call (used for multiple iterance).
//
//     *BUGS: If an or-mask "|xxx" was defined (pure obligation or-mask), the 
//            neo_getopt(...,OPT_NOW) failed when no options are passed to the command line. 
//            To avoid this beaviour and permit a subsequent usage+exit call, when -h is given, 
//            we implicit assume that masks check are not relevant, and neo_getopt() is 
//            forced to return.  
//             
//
//      neoverbose = 1;

	printf("OPT_NOW ...\n");
	neo_getopt(argc, argv, opt, OPT_NOW);

	printf("OPT_DELAYED ...\n");
	while ((i = neo_getopt(argc, argv, opt, OPT_DELAYED)) != EOF) {
		switch (i) {
		case '?':
			printf("unknown ? opt: neoptarg=%s\n", neoptarg);
			break;
		case 'h':
                        // int
                        // neo_usage(FILE *, char *custom_message, struct neo_options array[]); 
                        //
                        // print the usage() program in a classic fashion.
                        // if custom_message is NULL, a predefined header is printed.
                        //
                        // ie:
                        // neo_usage(stderr, "usage: prog blhablhabblha", opt);

			neo_usage(stderr, NULL, opt);
			exit(1);
			break;
		case '!':
                        // int
                        // neo_showdepend(FILE *, struct neo_options array[]);
                        //
                        // show the dependencies, printing (and) and (or) mask in a 
                        // classic fashion.
                        //

			neo_showdepend(stderr, opt);
			exit(1);
			break;
		default:
			printf("opt: %-c given, neoptarg=%s\n", i,neoptarg);
			break;
		}
	}

        argc -= neoptind;
        argv += neoptind;

	printf("done :-)\n");
	return (0);
}
#endif
