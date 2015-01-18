#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <net/if_arp.h>

#define MAXBYTES2CAPTURE 2048
#define ARP_REQUEST 1   
#define ARP_REPLY 2


void capturarPaquetesDesdeRed(char*dev,char*protocolo);


void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet){ 
	static int count = 0; //inicializamos el contador
	count ++;
	struct ether_header *h_ethernet;
	struct ether_arp *h_arp;
	int size_ethernet=sizeof(struct ether_header);//tamaño de la cabezera ethernet
	h_ethernet = (struct ether_header *) packet;//Apuntamos a la cabezera Ethernet que esta al comienzo de packet
	printf("Paquete numero: %d\n",count);
	printf("MAC origen: %s\n", ether_ntoa((struct ether_addr *)h_ethernet->ether_shost));
	printf("MAC destino: %s\n", ether_ntoa((struct ether_addr *)h_ethernet->ether_dhost) );

	h_arp=(struct ether_arp*)(packet+size_ethernet);//se apunta al paquete arp
	if(ntohs(h_arp->ea_hdr.ar_op)==ARP_REQUEST){
		printf("ARP Request\n");
	}else{
		printf("ARP REPLY\n");
	}

}


int main(int argc,char **argv)
{
	char *dev;
	char *protocolo;
    dev="wlan0";
    protocolo="arp";
 	capturarPaquetesDesdeRed(dev,protocolo);
	return 0;
}


void capturarPaquetesDesdeRed(char*device,char*protocol){
	printf("Opening device: %s\n",device);
	printf("Packets type: %s \n",protocol);
	int value=-1;//para capturar paquetes indefinidamente
	pcap_t *descr;//descriptor para la captura, especifica el numero maximo de bytes a capturar, modo de apertura: 0 normal, !=0 promiscuo
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program filter_protocol; 
	bpf_u_int32 dev_mask; // mascara de subred
	bpf_u_int32 dev_net; // direccion de red


	if( (descr = pcap_open_live(device,MAXBYTES2CAPTURE,value,1000,errbuf))==NULL){
		//Reportar error
		printf("\n pcap_open_live %s\n",errbuf);
		return;
	}

	pcap_lookupnet(device, &dev_net, &dev_mask, errbuf);

	//se obtiene la direccion de red y la mascara de la interfaz de red que se hara la captura
	 // Compilar la expresion filtro
    
    if(pcap_compile(descr, &filter_protocol, protocol, 0, dev_net) == -1){
    	//Reportar error
        printf("\npcap_compile() failed\n");
        return;
    }
    
    //Establece el filtro compilado arriba
    if(pcap_setfilter(descr,&filter_protocol)==-1){
    	//Reportar error
    	printf("\npcap_setfilter() failed\n");
    	return;
    }
    
     //entramos en el bucle infinito de captura de paquetes	
    int num_packets=200;
	if(pcap_loop(descr,num_packets,my_callback,NULL)==-1){
		printf("%s\n",pcap_geterr(descr));
		return;
	}

}

void capturarPaquetesDesdeArchivo(char*device,char*file_name){

	printf("Hola Mundo");

}