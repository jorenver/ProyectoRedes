
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
#define MAXBYTES2CAPTURE 2048
#define TAM 18


/***********************************
Archivo: arpdespoof.c
Fecha: 24/01/15
Autores: Oswaldo Bayona, Rodrigo Castro, Jorge Vergara
Compilacion: gcc arpdespoof.c -o arpdespoof -lpcap
Proyecto que lee trafico de red desde un archivo o interfaz y detecta ataques ARP

***********************************/


typedef enum{ REQUEST=1, REPLY} ARPtype; 



//Estructura usada para guardar informacion relevante del ARP
typedef struct infoARP{
    char* targetIP;
    char* sourceIP;	
    char* targetMac;
    char* sourceMac;
    double timestamp;
    ARPtype type;
}infoARP;

typedef struct Tuple {
	infoARP *request;
	infoARP	*reply;
}Tuple;//Representa un par ordenado: (request,reply)

////////////Lista de nodos enlazados ////////////////////
typedef struct nodelist{
	Tuple*tupla;
    struct nodelist *next;
}nodelist;

typedef struct list{
   nodelist* header, *last;
}list;

//Funciones de la lista//
void nodeListSetNext(nodelist *p, nodelist *q);
nodelist*nodelistNew(Tuple *t);
list*listNew();
int listIsEmpty(list *L);
void listAdd(list*lista,nodelist*node);
/////////////////////////////////////////

infoARP* infoARPNew(char*targetIP,char*sourceIP,char*targetMac,char*sourceMac,double timestamp,ARPtype type);
Tuple *tupleNew(infoARP*request);
void imprimirAmenaza(char* targetip, char* sourceMac, char* targetMac,double seconds);
void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void listarInterfaces();
void capturarPaquetesDesdeRed(char*device,char*protocol);
void capturarPaquetesDesdeArchivo(char*filename,char*protocol);
void detectarAtaque(infoARP*newReply);
int esRespuesta(infoARP*request,infoARP*reply);
int compararReply(infoARP*reply_uno,infoARP*reply_dos);


list* listaARP;//inicializamos la lista
double timeConfig;//tiempo 

int main(int argc,char **argv)
{
    char *dev,*protocol,*filename;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 pMask;            
    bpf_u_int32 pNet;             
    pcap_if_t *alldevs, *d;
    char comando[2];
    int flaq = 1;
    filename = (char*)malloc(sizeof(char)*20);
    dev = (char*)malloc(sizeof(char)*20);
	
    listaARP=listNew();    
    timeConfig=5.0;
    
    int opcion;//1 para hacer sniffing desde la red y 2 para hacerlo desde un archivo
    printf("\n******Arpdespoof******\n");  
    
    do{
	printf("Ingrese un comando: -i, -r, -t, -c: continuar :\n");
	scanf("%s",comando );
	
	if(!strcmp(comando, "-i")){
	     printf("\nInterfaces de Red:\n");
             listarInterfaces();  
             printf("\nIngrese una interfaz: ");
             scanf("%s",dev);
             opcion = 1;	
	}
	else if(!strcmp(comando, "-r")){
	    printf("\nIngrese el nombre del archivo: ");
	    opcion = 2;
    	    scanf("%s", filename);
	}
	else if(!strcmp(comando, "-t")){
	    printf("\nIngrese el tiempo en segundos: ");
	    scanf("%lf",&timeConfig);
	}
	else if(!strcmp(comando, "-c")){		
		flaq= 0;
	}
	else{
	   printf("\nDEBUG: Comando invalido\n");
	}
  
    }while(flaq);
  

    if(opcion==1){
        protocol="arp";
    	capturarPaquetesDesdeRed(dev,protocol);
    }else{
    	capturarPaquetesDesdeArchivo(filename,"arp");
    }
    return 0;
}



void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet){ 

	struct ether_header *h_ethernet;
	struct ether_arp *h_arp;

	int size_ethernet=sizeof(struct ether_header);//tamaño de la cabezera ethernet
	h_ethernet = (struct ether_header *) packet;//Apuntamos a la cabezera Ethernet que esta al comienzo de packet
	
	//tiempo de llegada del mensaje
	time_t seconds = (pkthdr->ts).tv_sec;
	suseconds_t microseconds = (pkthdr->ts).tv_usec;	
	double tiempo=seconds + (microseconds/1000000.0) ;
	

	h_arp=(struct ether_arp*)(packet+size_ethernet);
	/*
	(packet+size_ethernet) da la direccion base dentro del paquete en donde empieza el mensaje arp
	ether_arp tiene un campo de tipo arphd llamado ea_hdr: este campo contiene la informacion de tamaño fija dentro del mensaje
	como: Tipo y longitud de hardware, tipo y longitud de protocolo y op_code: operacion(ar_op) que pueden ser REQUEST o REPLY
	*/
	//Informacion del paquete ARP
	
	char*senderMac=(char*)malloc(sizeof(char)*TAM);
	char*senderIp=(char*)malloc(sizeof(char)*TAM);
	char*targetMac=(char*)malloc(sizeof(char)*TAM);
	char*targetIp=(char*)malloc(sizeof(char)*TAM);
	ARPtype type;

	strcpy(senderMac,(ether_ntoa((struct ether_addr*)h_arp->arp_sha)));
	strcpy(senderIp,inet_ntoa(*((struct in_addr*)h_arp->arp_spa) ));
	strcpy(targetMac,ether_ntoa((struct ether_addr*)h_arp->arp_tha));
	strcpy(targetIp,inet_ntoa(*( (struct in_addr*) h_arp->arp_tpa) ));
	type=ntohs(h_arp->ea_hdr.ar_op);
	/*
	char *ether_ntoa (const struct ether_addr *argumento);esta funcion convierte la direccion MAC contenida en "argumento" en un string leible
	char *inet_ntoa (struct in_addr argumento); esta funcion convierte la direccion IP contenida en "argumento" en un string leible 
	in_addr es un entero de 32 bits sin signo (uint32_t) 
	en ether_arp las direcciones IP estan definidas como un arreglo de 4 elementos, cada uno de tipo u_int8_t 
	Hay que enviarle el primer elemento de ese arreglo a la funcion inet_ntoa para que se realize la conversion correctamentes
	*/
	/* la instruccion : *( (struct in_addr*) h_arp->arp_spa) es lo mismo que
	struct in_addr *direccion_ip=(struct in_addr*)h_arp->arp_spa
	//struct in_addr contenido_dir=*direccion_ip;
	//inet_ntoa(contenido_dir);
	*/
	//printf("DEBUG: ARP Sender MAC adress %s\n",senderMac);
	//printf("DEBUG: ARP Sender IP adress %s\n",senderIp);
	//printf("DEBUG: ARP Target MAC adress %s\n",targetMac);
	//printf("Debug: ARP Target IP adress %s\n",targetIp);

	if(type==REQUEST){
		infoARP *newRequest=infoARPNew(senderMac,senderIp,targetMac,targetIp,tiempo,REQUEST);
		listAdd(listaARP,nodelistNew(tupleNew(newRequest)));//inserta request en la tupla, se inserta la tupla en la lista
	}else{
		if(!listIsEmpty(listaARP)){
			infoARP *newReply=infoARPNew(senderMac,senderIp,targetMac,targetIp,tiempo,REPLY);
			detectarAtaque(newReply);
		}
	}
}

void detectarAtaque(infoARP*newReply){
	nodelist*it;
	Tuple*currentTuple;
	infoARP *currentRequest;
	double t;
	for(it=listaARP->header;it!=NULL;it=it->next){
		currentTuple=it->tupla;
		currentRequest=currentTuple->request;
		if(esRespuesta(currentRequest,newReply)){
			t=newReply->timestamp-currentRequest->timestamp;
			if(t<=timeConfig){
				if(currentTuple->reply==NULL){
					currentTuple->reply=newReply;
					break;
				}else{
					if(!compararReply(currentTuple->reply,newReply)){
						imprimirAmenaza(currentRequest->targetIP,currentTuple->reply->sourceMac,newReply->sourceMac,newReply->timestamp);
					}
				}
			}
		}
	}
}

int esRespuesta(infoARP*request,infoARP*reply){
	if( (strcmp(request->sourceMac,reply->targetMac)==0) &&
		(strcmp(request->sourceIP,reply->targetIP)==0) &&
		(strcmp(request->targetIP,reply->sourceIP)==0)
		){
		return 1;
	}
	return 0;
}

int compararReply(infoARP*reply_uno,infoARP*reply_dos){
	if( (strcmp(reply_uno->sourceMac,reply_dos->sourceMac)==0) &&
		(strcmp(reply_uno->sourceIP,reply_dos->sourceIP)==0) &&
		(strcmp(reply_uno->targetMac,reply_dos->targetMac)==0) &&
		(strcmp(reply_uno->targetIP,reply_dos->targetIP))==0){
		return 1;
	}
	return 0;	
}




void imprimirAmenaza(char* targetip, char* sourceMac, char* targetMac,double seconds){
	printf("DETECT: who-has %s, R1: %s, R2: %s, TS: %lf\n",targetip,sourceMac,targetMac,seconds);
}

infoARP*infoARPNew(char*sourceMac,char*sourceIP,char*targetMac,char*targetIP,double timestamp,ARPtype type){
	infoARP*p=(infoARP*)malloc(sizeof(infoARP));
	
	p->sourceMac=(char*)malloc(sizeof(strlen(sourceMac)));//separa memoria
	strcpy(p->sourceMac,sourceMac);//copia cadena

	p->sourceIP=(char*)malloc(sizeof(strlen(sourceIP)));//separa memoria
	strcpy(p->sourceIP,sourceIP);//copia cadena

	p->targetMac=(char*)malloc(sizeof(strlen(targetMac)));//separa memoria
	strcpy(p->targetMac,targetMac);//copia cadena

	p->targetIP=(char*)malloc(sizeof(strlen(targetIP)));//separa memoria
	strcpy(p->targetIP,targetIP);//copia cadena

	p->timestamp=timestamp;
	p->type=type;

	return p;
}

Tuple *tupleNew(infoARP*request){
	Tuple*t=(Tuple*)malloc(sizeof(Tuple));
	t->request=request;
	t->reply=NULL;
	return t;
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


void capturarPaquetesDesdeRed(char*device,char*protocol){
	printf("DEBUG: Opening device: %s\n",device);
	int value=-1;//para capturar paquetes indefinidamente
	pcap_t *descr;//descriptor para la captura, especifica el numero maximo de bytes a capturar, modo de apertura: 0 normal, !=0 promiscuo
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program filter_protocol; 
	bpf_u_int32 dev_mask; // mascara de subred
	bpf_u_int32 dev_net; // direccion de red


	if( (descr = pcap_open_live(device,MAXBYTES2CAPTURE,value,1000,errbuf))==NULL){
		//Reportar error
		printf("\n DEBUG: Error in pcap_open_live %s\n",errbuf);
		return;
	}

	pcap_lookupnet(device, &dev_net, &dev_mask, errbuf);

	//se obtiene la direccion de red y la mascara de la interfaz de red que se hara la captura
	 // Compilar la expresion filtro
    
    if(pcap_compile(descr, &filter_protocol, protocol, 0, dev_net) == -1){
    	//Reportar error
        printf("\nDEBUG: Error in pcap_compile() \n");
        return;
    }
    
    //Establece el filtro compilado arriba
    if(pcap_setfilter(descr,&filter_protocol)==-1){
    	//Reportar error
    	printf("\nDEBUG: Error in pcap_setfilter()\n");
    	return;
    }
    
     //entramos en el bucle infinito de captura de paquetes	
    int num_packets=200;
	if(pcap_loop(descr,num_packets,my_callback,NULL)==-1){
		printf("DEBUG: Error in pcap_loop() %s\n",pcap_geterr(descr));
		return;
	}
	pcap_close(descr);

}


void capturarPaquetesDesdeArchivo(char*filename,char*protocol){
	struct bpf_program filter_protocol; 
	pcap_t *descr;//descriptor para la captura, especifica el numero maximo de bytes a capturar, modo de apertura: 0 normal, !=0 promiscuo
	char errbuf[PCAP_ERRBUF_SIZE];
	int num_packets=200;
	bpf_u_int32 dev_net; // direccion de red
	descr=pcap_open_offline(filename,errbuf);

    if(descr == NULL){
        printf("DEBUG: Error in pcap_open_offline() %s\n", errbuf);
        return ;
    }

    if(pcap_loop(descr,num_packets, my_callback, NULL)==-1){
    	printf("DEBUG: Error in pcap_loop() %s\n",pcap_geterr(descr));
		return;
    }
    pcap_close(descr);
}

//Funciones de la lista
nodelist*nodelistNew(Tuple *t){
	nodelist*n=(nodelist*)malloc(sizeof(nodelist));
	n->tupla=t;
	n->next=NULL;
	return n;
}

void nodeListSetNext(nodelist *p, nodelist *q){
    p->next = q;
}


list*listNew(){
	list*l=(list*)malloc(sizeof(list));
	l->header=NULL;
	l->last=NULL;
	return l;
}

int listIsEmpty(list *L){
    return (L->header == NULL && L->last == NULL);
}

void listAdd(list*lista,nodelist*node){
	if(listIsEmpty(lista))
        lista->header = lista->last = node;
    else {
        nodeListSetNext(lista->last, node);
        lista->last = node;   
    }
}
