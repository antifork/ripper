#include <stdio.h>

#define ROUTES "routes.conf"

int main(int argc, char **argv)
{
  FILE *fd;
  int nroute, i;
  char route[4][15];

  printf("\n\n Routes' File Generator ]Part of RiPPeR[ by mydecay && click\n\n");

  if (argc < 2) {
	  if ((fd = fopen(ROUTES, "w+")) < 0) {
		  perror("fopen()");
		  exit(1);
	  }
  } else {
	if ((fd = fopen(argv[1], "w+")) < 0) {
		perror("fopen()");
		exit(1);
	}
  }


  printf("How many routes do you wanna inject? ");
  scanf("%u", &nroute);

  if (nroute > 25) {
	  fprintf(stderr, "\nYou cannot inject more than 25 routes\n\n");
	  exit(1);
  }

  fprintf(fd, "%u\n", nroute);

  for (i = 0; i < nroute; i++) {

	  printf("\nRoute #%u\n\n", i+1);
  
	  printf("Route -> ");
	  scanf("%15s", &route[0]);
	  printf("Netmask -> ");
	  scanf("%15s", &route[1]);
	  printf("Gateway -> ");
	  scanf("%15s", &route[2]);
	  printf("Metric -> ");
	  scanf("%15s", &route[3]);
 
  	  fprintf(fd, "%u %u %u %u\n", inet_addr(&route[0]), inet_addr(&route[1]), inet_addr(&route[2]), inet_addr(&route[3]));
  }

  fclose(fd);
  
  return 0;
}
