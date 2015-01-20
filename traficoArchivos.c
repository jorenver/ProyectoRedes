
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
#include <netinet/ether.h>

#include <net/ethernet.h>
#include <net/if_arp.h>
#include <string.h>

void imrpimirAmenaza(char* targetip, char* sourceMac, char* targetMac,long int seconds, long int microseconds );
void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet);


typedef enum{ REQUEST, REPLY} ARPtype; 

//Estructura usada para guardar informacion relevante del ARP
typedef struct infoARP{
    char* targetIP;
    char* sourceIP;	
    char* targetMac;
    char* sourceMac;
    long int timestamp;
    ARPtype type;
}infoARP;


typedef struct nodelist{
    infoARP* cont;
    infoARP* next;
}nodelist;

typedef struct list{
   nodelist* header, *last;
}list;

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
        printf("DEBUG: %s\n", errbuf);
        return -1;
    }

    int num_packets=200;

    if(pcap_loop(descr,num_packets, my_callback, NULL)==-1){
    	printf("DEBUG: %s\n",pcap_geterr(descr));
		return;
    }

    pcap_close(descr);

    return 0;
}



void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet){ 
	static int count = 0; //inicializamos el contador
	count ++;
	struct ether_header *h_ethernet;
	struct ether_arp *h_arp;
	int size_ethernet=sizeof(struct ether_header);//tamaño de la cabezera ethernet
	h_ethernet = (struct ether_header *) packet;//Apuntamos a la cabezera Ethernet que esta al comienzo de packet
	printf("\nPacket Number: %d\n",count);
	time_t seconds = (pkthdr->ts).tv_sec;
	suseconds_t microseconds = (pkthdr->ts).tv_usec;	
printf("\n Recibido a las %ld.%ld segundos\n", seconds, microseconds );
	printf("MAC source: %s\n", ether_ntoa((struct ether_addr *)h_ethernet->ether_shost));
	printf("MAC destination: %s\n", ether_ntoa((struct ether_addr *)h_ethernet->ether_dhost) );

	h_arp=(struct ether_arp*)(packet+size_ethernet);
	/*
	(packet+size_ethernet) da la direccion base dentro del paquete en donde empieza el mensaje arp
	ether_arp tiene un campo de tipo arphd llamado ea_hdr: este campo contiene la informacion de tamaño fija dentro del mensaje
	como: Tipo y longitud de hardware, tipo y longitud de protocolo y op_code: operacion(ar_op) que pueden ser REQUEST o REPLY
	*/
	if(ntohs(h_arp->ea_hdr.ar_op)==1){
		printf("ARP Request\n");
	}else{
		printf("ARP REPLY\n");
	}
	/*
	char *ether_ntoa (const struct ether_addr *argumento);esta funcion convierte la direccion MAC contenida en "argumento" en un string leible
	char *inet_ntoa (struct in_addr argumento); esta funcion convierte la direccion IP contenida en "argumento" en un string leible 
	in_addr es un entero de 32 bits sin signo (uint32_t) 
	en ether_arp las direcciones IP estan definidas como un arreglo de 4 elementos, cada uno de tipo u_int8_t 
	Hay que enviarle el primer elemento de ese arreglo a la funcion inet_ntoa para que se realize la conversion correctamentes
	*/

	printf("Sender MAC addres %s\n",ether_ntoa((struct ether_addr*)h_arp->arp_sha));
	/* la instruccion : *( (struct in_addr*) h_arp->arp_spa) es lo mismo que
	struct in_addr *direccion_ip=(struct in_addr*)h_arp->arp_spa
	//struct in_addr contenido_dir=*direccion_ip;
	//inet_ntoa(contenido_dir);
	*/
	printf("Sender IP addres %s\n", inet_ntoa(*( (struct in_addr*) h_arp->arp_spa) ));
	
	printf("Target MAC addres %s\n",ether_ntoa((struct ether_addr*)h_arp->arp_tha));

	printf("Target IP addres %s\n", inet_ntoa(*( (struct in_addr*) h_arp->arp_tpa) ));

}




void imrpimirAmenaza(char* targetip, char* sourceMac, char* targetMac,long int seconds, long int microseconds ){
	printf("DETECT: who-has %s, R1: %s, R2: %s, TS: %ld.%ld", targetip, sourceMac, targetMac, seconds, microseconds);

}



