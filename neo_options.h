/*
 * $Id$
 * neo_options
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

#ifndef NEO_OPTIONS_H
#define NEO_OPTIONS_H

#include <unistd.h>

#define OPT_NOW		1
#define OPT_DELAYED	2

enum args { 
    no_argument=1,
    required_argument,
};

struct neo_options {
    int opt;
    enum args has_arg;
    char *depend;
    char *arg;
    char *usage;
};

typedef unsigned char REG;

int neo_usage (FILE *, char *, struct neo_options *);
int neo_showdepend (FILE *, struct neo_options *);
int neo_getopt (int , char *const[] , struct neo_options *, int);

#ifdef NEO_LIBRARY

#define bit         >>3
#define kbit        <<7
#define mbit        <<17
#define gbit        <<27

#define kbyte       <<10
#define mbyte       <<20
#define gbyte       <<30

#define REG_BS(r,b)      ( r[b>>3] |=   1<<(b&7) )
#define REG_BR(r,b)      ( r[b>>3] &= ~ 1<<(b&7) )
#define REG_BT(r,b)      ( r[b>>3]  &   1<<(b&7) )
#define REG_BN(r,b)      ( r[b>>3] ^=   1<<(b&7) )


#define REG_FOREACH(len)	int i; for(i=0;i<len ;i++)

#define REG_CLR(r,b)    memset((void *)(r),0,(b))

#define REG_NOT(r,b)   ({			\
REG_FOREACH(b)					\
        r[i] = ~r[i];                           \
})

#define REG_AND(s,d,b) ({			\
REG_FOREACH(b)                                  \
	d[i] &= s[i];				\
})

#define REG_OR(s,d,b)  ({ 			\
REG_FOREACH(b)                                  \
        d[i] |= s[i];                           \
})

#define REG_XOR(s,d,b) ({			\
REG_FOREACH(b)                                  \
        d[i] ^= s[i];                           \
})

#define REG_CPY(s,d,b) ({                       \
REG_FOREACH(b)                                  \
        d[i] = s[i];                            \
})

#define REG_CMP(s,d,b) ({			\
int j=0;                               		\
REG_FOREACH(b)                                  \
        j |= d[i]^s[i];				\
!j;						\
})

#define REG_ISNULL(r,b) ({ 			\
int j=0;                               		\
REG_FOREACH(b)                                  \
        j |= r[i];                       	\
!j;                                     	\
})

#endif /* NEO_LIBRARY */
#endif /* NEO_OPTIONS_H */
