#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <libnet.h>
#include <pcap.h>
#include <errno.h>
#include "bpf.h"
#include "neo_getopt.h"
#include "flags.h"
#include "config.h"

#ifdef HAVE_LIBNCURSES
#include <menu.h>
#endif

#ifdef __OpenBSD__
#include <netinet/ip.h>
#include <netinet/udp.h>
#endif

#define BUFLEN 		1500
#define RIP_PORT 	520
#define RIP_GROUP 	"224.0.0.9"

#define ROUTE		0
#define	NETMASK		1
#define	GW		2
#define	METRIC		3

#define BOLD   		"\033[1m"
#define NORMAL 		"\033[0m"

struct net_param {
	char *dev;
	unsigned long localaddr;
	unsigned long localnet;
	int num;
	char password[16];
	unsigned long rip_group;
	unsigned int routes[4][25];
};

/*Ncurses support variables*/
u_short graph;

/*n_menu.c*/
char n_route[16];
char n_spoof[16];
char n_metric[2];
char n_gateway[16];
char n_netmask[16];
char routemake_file[50];

/*end*/

#define RIPLEN		sizeof(struct rip)
#define RIPMSGLEN	sizeof(struct rip_message)
#define AUTHLEN		sizeof(struct authentication)

struct rip_message {
	unsigned short family;
	unsigned short tag;
	unsigned long ip;
	unsigned long netmask;
	unsigned long gateway;
	unsigned long metric;
};

struct rip {
	unsigned char command;
	unsigned char version;
	unsigned short domain;
};

struct authentication {
	unsigned short flag;
	unsigned short auth_type;
	char passwd[16];
};

/* Main function prototypes */

unsigned short in_cksum (unsigned short *, int);
void usage (char *);
void credits ();
void send_fake_rip_response (struct net_param *);
void check_injection (struct net_param *);
void init_all (struct net_param *);
int scan_net (char *);
void rip_file_read (char *, struct net_param *);
void sniff_passwd (struct net_param *);
void auth_pass (struct net_param *);
void fatal (char *pattern, ...) __attribute__ ((noreturn, weak));
int neo_getopt (int, char *const[], const struct neo_options *, int);
void check_injection_crypt (struct net_param *);
void *select_check(unsigned long);
void *select_main(unsigned long);

/* ncurses functions */ 
void n_print(char *wins, int y, int x, char *string, ...);
int ng_print(char *wins, int y, int x, char *string);

#ifdef HAVE_LIBNCURSES
int main_graph(struct net_param);
int n_scan_net(char *);
#endif
/* end ncurses*/
