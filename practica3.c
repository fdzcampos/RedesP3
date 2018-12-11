/***************************************************************************
 practica3.c
 Inicio, funciones auxiliares y modulos de transmision implmentados y a implementar de la practica 4.
Compila con warning pues falta usar variables y modificar funciones
 
 Compila: make
 Autor: Jose Luis Garcia Donado, Jorge E. Lopez de Vergara Mendez
 2018 EPS-UAM v1
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "interface.h"
#include "practica3.h"

/***************************Variables globales utiles*************************************************/
pcap_t* descr, *descr2; //Descriptores de la interface de red
pcap_dumper_t * pdumper;//y salida a pcap
uint64_t cont=0;	//Contador numero de mensajes enviados
char interface[10];	//Interface donde transmitir por ejemplo "eth0"
uint16_t ID=1;		//Identificador IP
uint16_t ID_ICMP=1; //Campo identificador ICMP
uint16_t ID_IP=1; //Campo identificador IP
uint16_t NSEQ_ICMP=0;  //Numero de secuencia ICMP

void handleSignal(int nsignal){
	printf("Control C pulsado (%"PRIu64")\n", cont);
	pcap_close(descr);
	exit(OK);
}

int main(int argc, char **argv){	

	char errbuf[PCAP_ERRBUF_SIZE];
	char fichero_pcap_destino[CADENAS];
	uint8_t IP_destino_red[IP_ALEN];
	uint16_t MTU;
	uint16_t datalink;
	uint16_t puerto_destino;
	char data[IP_DATAGRAM_MAX];
	uint16_t pila_protocolos[CADENAS];
	FILE *fd;

	int long_index=0;
	char opt;
	char flag_iface = 0, flag_ip = 0, flag_port = 0, flag_file = 0, bit_DF = 0, flag_mostrar = 0;

	static struct option options[] = {
		{"if",required_argument,0,'1'},
		{"ip",required_argument,0,'2'},
		{"pd",required_argument,0,'3'},
		{"f",required_argument,0,'4'},
		{"d",no_argument,0,'5'},
		{"m",no_argument,0,'6'},
		{"h",no_argument,0,'7'},
		{0,0,0,0}
	};

		//Dos opciones: leer de stdin o de fichero, adicionalmente para pruebas si no se introduce argumento se considera que el mensaje es "Payload "
	while ((opt = getopt_long_only(argc, argv,"1:2:3:4:5:6:7", options, &long_index )) != -1) {
		switch (opt) {

			case '1' :

				flag_iface = 1;
				//Por comodidad definimos interface como una variable global
				sprintf(interface,"%s",optarg);
				break;

			case '2' :

				flag_ip = 1;
				//Leemos la IP a donde transmitir y la almacenamos en orden de red
				if (sscanf(optarg,"%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"",
				                   &(IP_destino_red[0]),&(IP_destino_red[1]),&(IP_destino_red[2]),&(IP_destino_red[3])) != IP_ALEN){
					printf("Error: Fallo en la lectura IP destino %s\n", optarg);
					exit(ERROR);
				}

				break;

			case '3' :

				flag_port = 1;
				//Leemos el puerto a donde transmitir y la almacenamos en orden de hardware
				puerto_destino=atoi(optarg);
				break;

			case '4' :
				//Leemos la fuente de los datos que se van a enviar
				if(strcmp(optarg,"stdin")==0) {
					if (fgets(data, sizeof data, stdin)==NULL) {
						  	printf("Error leyendo desde stdin: %s %s %d.\n",errbuf,__FILE__,__LINE__);
						return ERROR;
					}
					sprintf(fichero_pcap_destino,"%s%s","stdin",".pcap");
				} else {
					sprintf(fichero_pcap_destino,"%s%s",optarg,".pcap");
					fd = fopen(optarg,"r");
			        if (fgets(data, sizeof data, fd)==NULL) {
			        	printf("Error leyendo desde %s: %s %s %d.\n",optarg,errbuf,__FILE__,__LINE__);
			            return ERROR;
					}
			        fclose(fd);
				}
				flag_file = 1;
				break;
				
			case '5' :
				bit_DF =1; // El usuario solicita que los paquetes se envien con el bit DF=1.
				break;

			case '6' :
				flag_mostrar =1; // El usuario solicita que se muestren en hexadecimal las tramas enviadas.
				break;

			case '7' : printf("Ayuda. Ejecucion: %s -if interface -ip direccion_IP -pd puerto [-f /ruta/fichero_a_transmitir o stdin] [-d] [-m]: %d\n",argv[0],argc); exit(ERROR);
				break;

			case '?' : 
			default: printf("Error. Ejecucion: %s -if interface -ip direccion_IP -pd puerto [-f /ruta/fichero_a_transmitir o stdin] [-d] [-m]: %d\n",argv[0],argc); exit(ERROR);
				break;
        }
    }

	if ((flag_iface == 0) || (flag_ip == 0) || (flag_port == 0)){
		printf("Error. Ejecucion: %s -if interface -ip direccion_IP -pd puerto [-f /ruta/fichero_a_transmitir o stdin] [-d] [-m]: %d\n",argv[0],argc);
		exit(ERROR);
	} else {
		printf("Interface:\n\t%s\n",interface);
		printf("IP:\n\t%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\n",IP_destino_red[0],IP_destino_red[1],IP_destino_red[2],IP_destino_red[3]);
		printf("Puerto destino:\n\t%"PRIu16"\n",puerto_destino);
		if (bit_DF) printf("Se solicita enviar paquete con bit DF=1\n");
		if (flag_mostrar) printf("Se solicita mostrar las tramas enviadas en hexadecimal\n");
	}

	if (flag_file == 0) {
		sprintf(data,"%s","Payload "); //Deben ser pares!
		sprintf(fichero_pcap_destino,"%s%s","debugging",".pcap");
	}

	if(signal(SIGINT,handleSignal)==SIG_ERR){
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		return ERROR;
	}
	//Inicializamos las tablas de protocolos
	if(inicializarPilaEnviar()==ERROR){
      	printf("Error leyendo desde stdin: %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	//Leemos el tamano maximo de transmision del nivel de enlace
	if(obtenerMTUInterface(interface, &MTU)==ERROR)
		return ERROR;
	//Descriptor de la interface de red donde inyectar trafico
	if ((descr = pcap_open_live(interface,MTU+ETH_HLEN,0, 0, errbuf)) == NULL){
		printf("Error: pcap_open_live(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}

	datalink=(uint16_t)pcap_datalink(descr); //DLT_EN10MB==Ethernet

	//Descriptor del fichero de salida pcap para debugging
	descr2=pcap_open_dead(datalink,MTU+ETH_HLEN);
	pdumper=pcap_dump_open(descr2,fichero_pcap_destino);

	//Formamos y enviamos el trafico, debe enviarse un unico segmento por llamada a enviar() aunque luego se traduzca en mas de un datagrama
	//Primero, un paquete ICMP; en concreto, un ping
	pila_protocolos[0]=ICMP_PROTO; pila_protocolos[1]=IP_PROTO; pila_protocolos[2]=ETH_PROTO;		// llenamos la pila de protocolos con los identificadores de cada protocolo
	Parametros parametros_icmp; 
	parametros_icmp.tipo=PING_TIPO; 
	parametros_icmp.codigo=PING_CODE;
	parametros_icmp.bit_DF=bit_DF;
	memcpy(parametros_icmp.IP_destino,IP_destino_red,IP_ALEN);
	if(enviar((uint8_t*)ICMP_DATA,strlen(ICMP_DATA),pila_protocolos,&parametros_icmp)==ERROR ){
		printf("Error: enviar(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	else	cont++;
	printf("Enviado mensaje %"PRIu64", ICMP almacenado en %s\n\n", cont,fichero_pcap_destino);

	//Luego, un paquete UDP
	//Definimos la pila de protocolos que queremos seguir
	pila_protocolos[0]=UDP_PROTO; pila_protocolos[1]=IP_PROTO; pila_protocolos[2]=ETH_PROTO;
	//Rellenamos los parametros necesario para enviar el paquete a su destinatario y proceso
	Parametros parametros_udp; memcpy(parametros_udp.IP_destino,IP_destino_red,IP_ALEN); parametros_udp.bit_DF=bit_DF; parametros_udp.puerto_destino=puerto_destino;
	//Enviamos
	if(enviar((uint8_t*)data,strlen(data),pila_protocolos,&parametros_udp)==ERROR ){
		printf("Error: enviar(): %s %s %d.\n",errbuf,__FILE__,__LINE__);
		return ERROR;
	}
	else	cont++;

	printf("Enviado mensaje %"PRIu64", almacenado en %s\n\n\n", cont,fichero_pcap_destino);

	//Cerramos descriptores
	pcap_close(descr);
	pcap_dump_close(pdumper);
	pcap_close(descr2);
	return OK;
}


/****************************************************************************************
 * Nombre: enviar                                                                       *
 * Descripcion: Esta funcion envia un mensaje                                           *
 * Argumentos:                                                                          *
 *  -mensaje: mensaje a enviar                                                          *
 *  -pila_protocolos: conjunto de protocolos a seguir                                   *
 *  -longitud: bytes que componen mensaje                                               *
 *  -parametros: parametros necesario para el envio (struct parametros)                 *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/
uint8_t enviar(uint8_t* mensaje, uint32_t longitud,uint16_t* pila_protocolos,void *parametros){
	uint16_t protocolo=pila_protocolos[0];
	printf("Enviar(%"PRIu16") %s %d.\n",protocolo,__FILE__,__LINE__);
	if(protocolos_registrados[protocolo]==NULL){
		printf("Protocolo %"PRIu16" desconocido\n",protocolo);
		return ERROR;
	} else {
		return protocolos_registrados[protocolo](mensaje,longitud,pila_protocolos,parametros);
	}
	return ERROR;
}


/***************************Pila de protocolos a implementar************************************/

/****************************************************************************************
 * Nombre: moduloICMP                                                                   *
 * Descripcion: Esta funcion implementa el modulo de envio ICMP                         *
 * Argumentos:                                                                          *
 *  -mensaje: mensaje a anadir a la cabecera ICMP                                       *
 *  -longitud: bytes que componen el mensaje                                            *
 *  -pila_protocolos: conjunto de protocolos a seguir                                   *
 *  -parametros: parametros necesario para el envio este protocolo                      *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/
uint8_t moduloICMP(uint8_t* mensaje, uint32_t longitud, uint16_t* pila_protocolos, void *parametros){
	uint8_t segmento[ICMP_DATAGRAM_MAX]={0};
	uint8_t aux8;
	uint8_t *posCheckSum;
	uint16_t aux16;
	uint32_t pos=0;
	uint8_t protocolo_inferior=pila_protocolos[1];
	
	printf("modulo ICMP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);
	Parametros icmpdatos=*((Parametros*)parametros);

	/* Se rellena el campo tipo del paquete ICMP*/
	aux8=icmpdatos.tipo;
	if(memcpy(segmento+pos,&aux8,sizeof(uint8_t)) == NULL) {
		printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
		return ERROR;
	}
	pos+=sizeof(uint8_t);

	/* Se rellena el campo codigo  del paquete ICMP */
	aux8=icmpdatos.codigo;
	if(memcpy(segmento+pos,&aux8,sizeof(uint8_t)) == NULL) {
		printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
		return ERROR;
	}
	pos += sizeof(uint8_t);

	// el checksum lo rellenamos al final, de momento lo dejamos a 0 y guardamos la posicion donde guardarlo en posCheckSum
	posCheckSum = segmento+pos;
	aux16=htons(0);
	if(memcpy(segmento+pos, &aux16, sizeof(uint16_t))==NULL){
		printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
		return ERROR;
	}
	pos += sizeof(uint16_t);

	/* Se rellena el campo identificador */
	aux16 = ntohs(ID_ICMP);
	if(memcpy(segmento+pos, &aux16, sizeof(uint16_t)) == NULL) {
		printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
		return ERROR;
	}
	ID_ICMP++;
	pos += sizeof(uint16_t);

	/* Se rellena el campo Numero de secuencia*/
	aux16 = ntohs(NSEQ_ICMP);
	if(memcpy(segmento+pos, &aux16, sizeof(uint16_t)) == NULL) {
		printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
		return ERROR;
	}
	NSEQ_ICMP++;
	pos += sizeof(uint16_t);

	/* Se rellena el campo datos */
	if(longitud > 48){
		printf("El mensaje es de mas de 48 Bytes\n");
	}
	if(memcpy(segmento+pos, mensaje, longitud) == NULL){
		printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
		return ERROR;
	}
	pos+=longitud;			// apuntamos al final de la parte de datos de ICMP

	/* Se rellena el campo suma de control del paquete ICMP */
	if(longitud%2 != 0){
		printf("El campo longitud del mensaje ICMP no es par");
		return ERROR;
	} 
	if( calcularChecksum(segmento, pos, (uint8_t *) &aux16) ){
		printf("Error al calcular el checksum de ICMP\n");
		return ERROR;
	}
	/*mostrarHex(aux16, sizeof(uint16_t));*/
	if( memcpy(posCheckSum, &aux16, sizeof(uint16_t)) == NULL ) {
		printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
		return ERROR;
	}

	//Se llama al protocolo definido de nivel inferior a traves de los punteros registrados en la tabla de protocolos registrados
	return protocolos_registrados[protocolo_inferior](segmento,pos,pila_protocolos,&icmpdatos);
}


/****************************************************************************************
 * Nombre: moduloUDP                                                                    *
 * Descripcion: Esta funcion implementa el modulo de envio UDP                          *
 * Argumentos:                                                                          *
 *  -mensaje: mensaje a enviar                                                          *
 *  -longitud: bytes que componen mensaje                                               *
 *  -pila_protocolos: conjunto de protocolos a seguir                                   *
 *  -parametros: parametros necesario para el envio este protocolo                      *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/
uint8_t moduloUDP(uint8_t* mensaje, uint32_t longitud, uint16_t* pila_protocolos, void *parametros){
	uint8_t segmento[UDP_SEG_MAX]={0};
	uint16_t puerto_origen = 0;
	uint16_t aux16;
	uint32_t pos=0;
	uint8_t protocolo_inferior=pila_protocolos[1];
	printf("modulo UDP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);

	if (longitud>UDP_SEG_MAX){
		printf("Error: mensaje demasiado grande para UDP (%d).\n",UDP_SEG_MAX);
		return ERROR;
	}

	Parametros udpdatos=*((Parametros*)parametros);
	uint16_t puerto_destino=udpdatos.puerto_destino;
	puerto_origen = 17;

	/*Rellenamos el puerto origen*/
	aux16=htons(puerto_origen);
	if(memcpy(segmento+pos,&aux16,sizeof(uint16_t)) == NULL) {
		printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
		return ERROR;
	}
	pos+=sizeof(uint16_t);

	/*Rellenamos el puerto destino*/
	aux16=htons(puerto_destino);
	if(memcpy(segmento+pos,&aux16,sizeof(uint16_t)) == NULL) {
		printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
		return ERROR;
	}
	pos+=sizeof(uint16_t);

	/*Rellenamos el campo longitud*/
	aux16=htons(longitud+8);										// longitude = mensaje + cabecera
	if(memcpy(segmento+pos,&aux16,sizeof(uint16_t)) == NULL) {
		printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
		return ERROR;
	}
	pos+=sizeof(uint16_t);

	/*Rellenamos la suma de control*/
	aux16 = 0;
	if(memcpy(segmento+pos, &aux16, sizeof(uint16_t)) == NULL) {
		printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
		return ERROR;
	}
	pos+=sizeof(uint16_t);

	if( memcpy(segmento+pos, mensaje, longitud) == NULL ) {
		printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
		return ERROR;
	}
	
	//Se llama al protocolo definido de nivel inferior a traves de los punteros registrados en la tabla de protocolos registrados
	return protocolos_registrados[protocolo_inferior](segmento,longitud+pos,pila_protocolos,parametros);
}


/****************************************************************************************
 * Nombre: moduloIP                                                                     *
 * Descripcion: Esta funcion implementa el modulo de envio IP                           *
 * Argumentos:                                                                          *
 *  -segmento: segmento a enviar                                                        *
 *  -longitud: bytes que componen el segmento                                           *
 *  -pila_protocolos: conjunto de protocolos a seguir                                   *
 *  -parametros: parametros necesario para el envio este protocolo                      *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/
uint8_t moduloIP(uint8_t* segmento, uint32_t longitud, uint16_t* pila_protocolos, void *parametros){
	uint8_t datagrama[IP_DATAGRAM_MAX]={0};
	uint8_t aux8;
	uint8_t IP_origen[IP_ALEN]={0};
	uint8_t protocolo_superior=pila_protocolos[0];
	uint8_t protocolo_inferior=pila_protocolos[2];
	uint8_t mascara[IP_ALEN],IP_rango_origen[IP_ALEN]={0},IP_rango_destino[IP_ALEN]={0};
	uint8_t *posCheckSum = NULL;
	uint16_t aux16, aux16_frag;
	uint16_t MTUaux;
	uint16_t posicionaux = 1;
	uint32_t aux32;
	uint32_t pos=0,pos_control=0;
	int i = 0;
	int flag = 0 ;  
	
	pila_protocolos++;   /*	Para apuntarlo a pila_protocolos[1]*/

	printf("modulo IP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);
	Parametros ipdatos=*((Parametros*)parametros);
	uint8_t* IP_destino=ipdatos.IP_destino;
	
	
	for(i=0; i<posicionaux; i++) {

		if( obtenerIPInterface(interface, IP_origen) == ERROR ){
			printf("Error en obtenerIPInterface\n");
			return ERROR;
		}
		/*Introducimos en el datagrama el campo version y IHL porque son 4 bits cada uno*/
		aux8 = 0b01000101;									/*Sin opciones ni relleno*/
		if(memcpy(datagrama+pos,&aux8,sizeof(uint8_t)) == NULL) {
			printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
			return ERROR;		
		}
		pos+=sizeof(uint8_t);

		/*Introducimos en el datagrama el campo Tipo Servicio*/
		aux8 = 0;													/* Todo a , la red de la autonoma, lo cambia a 0 por defecto */
		if(memcpy(datagrama+pos,&aux8,sizeof(uint8_t)) == NULL) {
			printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
			return ERROR;		
		}
		pos+=sizeof(uint8_t);
		
		/*Introducimos en el datagrama el campo Longitud Total*/
		aux16 = htons((uint16_t)longitud+20);											/* PREGUNTAR: ltotal = lcabecera (20) + ldatagrama */
		if(memcpy(datagrama+pos,&aux16,sizeof(uint16_t)) == NULL) {
			printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
			return ERROR;
		}
		pos+=sizeof(uint16_t);
		
		/*Introducimos en el datagrama el campo Identificacion*/
		aux16 = ID_IP;
		if(memcpy(datagrama+pos,&aux16,sizeof(uint16_t)) == NULL) {
			printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
			return ERROR;		
		}
		pos+=sizeof(uint16_t);

		printf("DEBUGUEANDO %d\n", ipdatos.bit_DF);
		/*Introducimos en el datagrama el campo Flags (reservado = 0, df, last fragment = 0) y la Posicion*/
		if( ipdatos.bit_DF == 0 ){	/*Queremos fragmentar, no hemos puesto el -d*/
			printf("XD\n");
			if(obtenerMTUInterface(interface, &MTUaux) == ERROR) {
				printf("Se ha producido un error obteniendo la mtu interface\n");
				return ERROR;
			}
			if(MTUaux < longitud+20) {
				posicionaux = (longitud+20)/(MTUaux);
				aux16 = 0b0000000000000000 || (uint16_t) i;

				if(i == posicionaux){
					aux16 = 0b0010000000000000 || (uint16_t) i;
				}
				aux16 = htons(aux16);
			}else{
				// no me hace falta fragmentar, todo sigue normal
				aux16 = htons(0b0000000000000000);
			}
		
		}else{		/*No queremos fragmentar, hemos puesto el -d*/
			// no puedo/debo, todo sigue normal
			// como se gestionan los errores si mtu < longitud
			aux16 = htons(0b0100000000000000);
		}

		if(memcpy(datagrama+pos, &aux16, sizeof(uint16_t)) == NULL) {
			printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
			return ERROR;		
		}
		pos+=sizeof(uint16_t);
		
		/*Introducimos en el datagrama el campo Tiempo de vida, maria dice que da igual*/
		aux8= 0b10000000;		/*Hemos puesto 128 bc ositos*/
		if(memcpy(datagrama+pos,&aux8,sizeof(uint8_t)) == NULL) {
			printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
			return ERROR;		
		}
		pos+=sizeof(uint8_t);

		/*Introducimos en el datagrama el campo Protocolo */
		aux8= protocolo_superior;
		if(memcpy(datagrama+pos,&aux8,sizeof(uint8_t)) == NULL) {
			printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
			return ERROR;
		}
		pos+=sizeof(uint8_t);

		/*Introducimos en el datagrama el campo suma de control de cabecera*/
		posCheckSum = datagrama+pos;
		aux16 = htons(0);											/*Se rellena a 0's y al final de la funcion se calcula*/
		if(memcpy(datagrama+pos,&aux16,sizeof(uint16_t)) == NULL) {
			printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
			return ERROR;
		}
		pos+=sizeof(uint16_t);

		/*Introducimos en el datagrama la direccion de origen*/
		if(memcpy(datagrama+pos,IP_origen,sizeof(uint8_t)*4) == NULL) {
			printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
			return ERROR;
		}
		pos+=sizeof(uint32_t);

		/*Introducimos en el datagrama la direccion de destino*/
		if(memcpy(datagrama+pos,IP_destino,sizeof(uint8_t)*4) == NULL) {
			printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
			return ERROR;		
		}
		pos+=sizeof(uint32_t);

		/*No tenemos datos ni relleno*/

		/*Realizamos la solicitud ARP*/
		if(obtenerMascaraInterface(interface, mascara) == ERROR){		/*Obtenemos la mascara que vamos a usar*/
			printf("ERROR en obtenerMascaraInterface\n");
			return ERROR;
		}

		if( aplicarMascara(IP_origen, mascara, 4, IP_rango_origen) == ERROR){		/*Aplicamos la mascara a la ip_origen*/
			printf("Error aplicando la mascara a la ip\n");
			return ERROR;
		}

		if( aplicarMascara(IP_destino, mascara, 4, IP_rango_destino) == ERROR){		/*Aplicamos la mascara a la ip_destino*/
			printf("Error aplicando la mascara\n");
			return ERROR;
		}

		/*Comparamos las IP por octectos, porque aunque, en nuestro caso no haya que hacerlo (se puede comparar a lo bruto), si hay un caso en que no son 4Bytes(IPv4) como IPv6
		tambien funciona :) */
		for(i=0; i<IP_ALEN; i++) {						
			if(IP_rango_destino[i] != IP_rango_origen[i] && flag == 0){
				flag = 1;
			}
		}

		/*Mandamos la solicitud ARP*/
		if(flag == 0) {		/*Caso en el que el retorno de las mascaras es igual, por lo tanto se pasa la ip_destino, que esta en la misma subred*/
			if(solicitudARP(interface, IP_destino, ipdatos.ETH_destino) == ERROR ){		/*se realiza la solicitud arp para la ip de destino*/
				printf("Error realizando la solicitud ARP a la ip destino\n");
				return ERROR;
			}
		} else {			/*Caso en el que el retorno de las mascaras es diferente, por lo tanto se le pasa la ip del router, porque la ip_dest no esta en la subred*/
			if (obtenerGateway(interface, &aux8) == ERROR){		/*Se obtiene la ip del router*/
				printf("Error obteniendo la gateway\n");
				return ERROR;
			}
			if(solicitudARP(interface, &aux8, ipdatos.ETH_destino) == ERROR){   	/*se realiza la solicitud arp para la ip del router*/				/* OJO CUIDAO */
				printf("Error realizando la solicitud ARP a la ip del router\n");
				return ERROR;
			}
		}

		/* Rellenamos el campo Checksum */
		if(calcularChecksum(datagrama, pos, (uint8_t*)&aux16) == ERROR){
			printf("Error al calcular el checksum de ICMP\n");
			return ERROR;
		}
		/* volvemos al campo checksum */
		if(memcpy(posCheckSum, &aux16, sizeof(uint16_t)) == NULL) {
			printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
			return ERROR;
		}

		// Encapsulamos ICMP
		if( memcpy(datagrama+pos, segmento, longitud) == NULL ) {
			printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
			return ERROR;
		}
	
	}

	//TODO A implementar el datagrama y fragmentación, asi como control de tamano segun bit DF
	return protocolos_registrados[protocolo_inferior](datagrama,longitud+pos,pila_protocolos,&ipdatos);
}


/****************************************************************************************
 * Nombre: moduloETH                                                                    *
 * Descripcion: Esta funcion implementa el modulo de envio Ethernet                     *
 * Argumentos:                                                                          *
 *  -datagrama: datagrama a enviar                                                      *
 *  -longitud: bytes que componen el datagrama                                          *
 *  -pila_protocolos: conjunto de protocolos a seguir                                   *
 *  -parametros: Parametros necesario para el envio este protocolo                      *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/
uint8_t moduloETH(uint8_t* datagrama, uint32_t longitud, uint16_t* pila_protocolos,void *parametros){
	uint16_t aux16,longitudMTU;
	uint8_t aux8;
	uint8_t mac_origen[ETH_ALEN]={0};
	uint8_t trama[ETH_FRAME_MAX]={0};
	uint32_t pos=0;
	struct timeval time;
	struct pcap_pkthdr hdr;
	int err_inject;

	printf("modulo ETH(fisica) %s %d.\n",__FILE__,__LINE__);	

	//Control de tamano
	if(obtenerMTUInterface(interface, &longitudMTU) == ERROR) {
		printf("Error obtenerMTUInterface\n");
		return ERROR;
	}
	if(longitud > longitudMTU) {
		return ERROR;
	}

	// Rellenamos el campo direccion ethernet destino
	if(memcpy(trama+pos,((Parametros*)parametros)->ETH_destino, sizeof(uint8_t)*ETH_ALEN) == NULL) {
		printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
		return ERROR;
	}
	pos+=sizeof(uint32_t);
	pos+=sizeof(uint16_t);

	// Rellenamos el campo direccion ethernet origen
	if(obtenerMACdeInterface(interface, mac_origen) == ERROR) {
		printf("Error obteniendo la mac de la interface\n");
		return ERROR;
	}

	if(memcpy(trama+pos,mac_origen, sizeof(uint8_t)*ETH_ALEN) == NULL) {
		printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
		return ERROR;
	}
	pos+=sizeof(uint32_t);
	pos+=sizeof(uint16_t);

	// Rellenamos el campo tipo ethernet
	aux16=htons(0x0800);
	if(memcpy(trama+pos,&aux16, sizeof(uint16_t)) == NULL) {
		printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
		return ERROR;
	}
	pos+=sizeof(uint16_t);
	
	// encapsulamos ip
	if( memcpy(trama+pos, datagrama, longitud) == NULL ) {
		printf("Error haciendo el memcpy %s %d\n", __FILE__,__LINE__);
		return ERROR;
	}

	//Enviar a capa fisica, comprobamos si es mayor de 60 ya que este es el maximo tamano a enviar
	if( ETH_MAX > longitud+14 ){
		if((err_inject=pcap_inject(descr, trama, ETH_MAX)) == -1 ) { 		// 14 es la longitud de la cabecera eth
			printf("Error inyectando el paquete, tipo de error %d\n", err_inject);
			return ERROR;
		}
	}else{
		if((err_inject=pcap_inject(descr, trama, longitud+14)) == -1) { 	// 14 es la longitud de la cabecera eth
			printf("Error inyectando el paquete, tipo de error %d\n", err_inject);
			return ERROR;
		}
	}
	
	//Almacenamos la salida por cuestiones de debugging [...]
	gettimeofday(&time,NULL);
    hdr.ts.tv_sec = time.tv_sec;
    hdr.ts.tv_usec = time.tv_usec;
    hdr.len = longitud+pos;
    hdr.caplen = longitud+pos;
    pcap_dump((u_char *)pdumper,&hdr,trama);

	return OK;
}



/***************************Funciones auxiliares a implementar***********************************/

/****************************************************************************************
 * Nombre: aplicarMascara                                                               *
 * Descripcion: Esta funcion aplica una mascara a una vector                            *
 * Argumentos:                                                                          *
 *  -IP: IP a la que aplicar la mascara en orden de red                                 *
 *  -mascara: mascara a aplicar en orden de red                                         *
 *  -longitud: bytes que componen la direccion (IPv4 == 4)                              *
 *  -resultado: Resultados de aplicar mascara en IP en orden red                        *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/
uint8_t aplicarMascara(uint8_t* IP, uint8_t* mascara, uint8_t longitud, uint8_t* resultado){

	if(!IP || !mascara) {
		return ERROR;
	} 

	/*Como la longitud en esta practica va a ser de 4 podemos hacer la and como se especifica abajo
	pero en otro caso habría que hacerlo por octetos con ayuda de un bucle, ya que la longitud puede ser de 32*/

	*resultado = IP && mascara;
	return OK;
}


/***************************Funciones auxiliares implementadas**************************** mostrarHex(uint8_t * datos, uint32_t longitud)**********/

/****************************************************************************************
 * Nombre: mostrarHex                                                                   *
 * Descripcion: Esta funcion imprime por pantalla en hexadecimal un vector              *
 * Argumentos:                                                                          *
 *  -datos: bytes que conforman un mensaje                                              *
 *  -longitud: Bytes que componen el mensaje                                            *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/
uint8_t mostrarHex(uint8_t * datos, uint32_t longitud){
	uint32_t i;
	printf("Datos:\n");
	for (i=0;i<longitud;i++){
		printf("%02"PRIx8" ", datos[i]);
	}
	printf("\n");
	return OK;
}


/****************************************************************************************
 * Nombre: calcularChecksum                                                             *
 * Descripcion: Esta funcion devuelve el ckecksum tal como lo calcula IP/ICMP           *
 * Argumentos:                                                                          *
 *   -datos: datos sobre los que calcular el checksum                                   *
 *   -longitud: numero de bytes de los datos sobre los que calcular el checksum         *
 *   -checksum: checksum de los datos (2 bytes) en orden de red!                        *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/
uint8_t calcularChecksum(uint8_t *datos, uint16_t longitud, uint8_t *checksum) {
    uint16_t word16;
    uint32_t sum=0;
    int i;
    // make 16 bit words out of every two adjacent 8 bit words in the packet
    // and add them up
    for (i=0; i<longitud; i=i+2){
        word16 = (datos[i]<<8) + datos[i+1];
        sum += (uint32_t)word16;       
    }
    // take only 16 bits out of the 32 bit sum and add up the carries
    while (sum>>16) {
        sum = (sum & 0xFFFF)+(sum >> 16);
    }
    // one's complement the result
    sum = ~sum;      
    checksum[0] = sum >> 8;
    checksum[1] = sum & 0xFF;
    return OK;
}


/***************************Funciones inicializacion implementadas*********************************/

/****************************************************************************************
 * Nombre: inicializarPilaEnviar                                                        *
 * Descripcion: inicializar la pila de red para enviar registrando los distintos modulos*
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/
uint8_t inicializarPilaEnviar() {
	bzero(protocolos_registrados,MAX_PROTOCOL*sizeof(pf_notificacion));
	/*Registramos el protocolo ETH en los protocolos registrados*/
	if(registrarProtocolo(ETH_PROTO, moduloETH, protocolos_registrados)==ERROR)
		return ERROR;
	/*Registramos el protocolo IP en los protocolos registrados*/
	if(registrarProtocolo(IP_PROTO, moduloIP, protocolos_registrados)==ERROR)
		return ERROR;
	/*Registramos el protocolo ICMP en los protocolos registrados*/
	if(registrarProtocolo(ICMP_PROTO, moduloICMP, protocolos_registrados)==ERROR)
		return ERROR;
	/*Registramos el protocolo UDP en los protocolos registrados*/
	if(registrarProtocolo(UDP_PROTO, moduloUDP, protocolos_registrados)==ERROR)
		return ERROR;

	return OK;
}


/****************************************************************************************
 * Nombre: registrarProtocolo                                                           *
 * Descripcion: Registra un protocolo en la tabla de protocolos                         *
 * Argumentos:                                                                          *
 *  -protocolo: Referencia del protocolo (ver RFC 1700)                                 *
 *  -handleModule: Funcion a llamar con los datos a enviar                              *
 *  -protocolos_registrados: vector de funciones registradas                            *
 * Retorno: OK/ERROR                                                                    *
 ****************************************************************************************/
uint8_t registrarProtocolo(uint16_t protocolo, pf_notificacion handleModule, pf_notificacion* protocolos_registrados){
	if(protocolos_registrados==NULL ||  handleModule==NULL){		
		printf("Error: registrarProtocolo(): entradas nulas.\n");
		return ERROR;
	}
	else
		protocolos_registrados[protocolo]=handleModule;
	return OK;
}


