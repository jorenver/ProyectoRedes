
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <string.h>

void imrpimirAmenaza(char* targetip, char* Mac1, char* Mac2, bpf_u_int32 timestamp );


void callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet){
  static int count = 1;

  printf("\nPacket number [%d], length of this packet is: %d\n", count++, pkthdr->len);
}

int main(int argc,char **argv)
{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    struct bpf_program fp;        /* to hold compiled program */
    bpf_u_int32 pMask;            /* subnet mask */
    bpf_u_int32 pNet;             /* ip address*/
    pcap_if_t *alldevs, *d;
    char dev_buff[64] = {0};
    int i =0;

    char *filename="trace2.pcap";

	descr=pcap_open_offline(filename,errbuf);

    if(descr == NULL)
    {
        printf("pcap_open_live() failed due to [%s]\n", errbuf);
        return -1;
    }

    int num_packets=200;

    if(pcap_loop(descr,num_packets, callback, NULL)==-1){
    	printf("%s\n",pcap_geterr(descr));
		return;
    }

    pcap_close(descr);

    return 0;
}




void imrpimirAmenaza(char* targetip, char* Mac1, char* Mac2, bpf_u_int32 timestamp ){
	printf("DETECT: who-has %s, R1: %s, R2: %s, TS: %d", targetip, Mac1, Mac2, timestamp);

}



