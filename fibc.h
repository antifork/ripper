#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <libnet.h>
#include <pcap.h>
#include <errno.h>
#include "bpf.h"
#include "neo_getopt.h"

#ifdef __OpenBSD__
#include <netinet/ip.h>
#include <netinet/udp.h>
#endif

#define BUFLEN 1500
#define RIP_PORT 520
#define RIP_GROUP "224.0.0.9"

char errbuf[PCAP_ERRBUF_SIZE], *dev;
unsigned long localaddr, localnet;
extern int errno;
int w;
char password[16];
unsigned int routes[4][25];
unsigned long flags;

struct rip_message
{
  unsigned short family;
  unsigned short tag;
  unsigned long ip;
  unsigned long netmask;
  unsigned long gateway;
  unsigned long metric;
};

struct rip
{
  unsigned char command;
  unsigned char version;
  unsigned short domain;
};

struct authentication
{
  unsigned short flag;
  unsigned short auth_type;
  char passwd[16];
};

/* Main function prototypes */

unsigned short in_cksum (unsigned short *, int);
void usage (char *);
void credits ();
void send_fake_rip_response ();
void check_injection ();
void init_all ();
int scan_net (char *);
void rip_file_read (char *);
void sniff_passwd ();
void auth_pass ();
void fatal (char *pattern, ...) __attribute__ ((noreturn, weak));
int neo_getopt (int, char *const[], const struct neo_options *, int);
void check_injection_crypt ();
