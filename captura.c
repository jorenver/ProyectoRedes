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
	printf("\nPacket Number: %d\n",count);
	printf("MAC source: %s\n", ether_ntoa((struct ether_addr *)h_ethernet->ether_shost));
	printf("MAC destination: %s\n", ether_ntoa((struct ether_addr *)h_ethernet->ether_dhost) );

	h_arp=(struct ether_arp*)(packet+size_ethernet);
	/*
	(packet+size_ethernet) da la direccion base dentro del paquete en donde empieza el mensaje arp
	ether_arp tiene un campo de tipo arphd llamado ea_hdr: este campo contiene la informacion de tamaño fija dentro del mensaje
	como: Tipo y longitud de hardware, tipo y longitud de protocolo y op_code: operacion(ar_op) que pueden ser REQUEST o REPLY
	*/
	if(ntohs(h_arp->ea_hdr.ar_op)==ARP_REQUEST){
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