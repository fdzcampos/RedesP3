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


	int long_index=0;
	char opt;
	char flag_iface = 0, flag_ip = 0, flag_port = 0, flag_file = 0, flag_dontfrag = 0, flag_mostrar = 0;

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

				if(strcmp(optarg,"stdin")==0) {
					if (fgets(data, sizeof data, stdin)==NULL) {
						  	printf("Error leyendo desde stdin: %s %s %d.\n",errbuf,__FILE__,__LINE__);
						return ERROR;
					}
					sprintf(fichero_pcap_destino,"%s%s","stdin",".pcap");
				} else {
					sprintf(fichero_pcap_destino,"%s%s",optarg,".pcap");
					//TODO Leer fichero en data [...]
				}
				flag_file = 1;
				break;
				
			case '5' :
				flag_dontfrag =1; // El usuario solicita que los paquetes se envien con el bit DF=1.
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
		if (flag_dontfrag) printf("Se solicita enviar paquete con bit DF=1\n");
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
	pila_protocolos[0]=ICMP_PROTO; pila_protocolos[1]=IP_PROTO; pila_protocolos[2]=ETH_PROTO;
	Parametros parametros_icmp; parametros_icmp.tipo=PING_TIPO; parametros_icmp.codigo=PING_CODE; parametros_icmp.bit_DF=flag_dontfrag; memcpy(parametros_icmp.IP_destino,IP_destino_red,IP_ALEN);
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
	Parametros parametros_udp; memcpy(parametros_udp.IP_destino,IP_destino_red,IP_ALEN); parametros_udp.bit_DF=flag_dontfrag; parametros_udp.puerto_destino=puerto_destino;
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
	}
	else {
		return protocolos_registrados[protocolo](mensaje,longitud,pila_protocolos,parametros);
	}
	return ERROR;
}


/***************************TODO Pila de protocolos a implementar************************************/


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
	uint16_t aux16;
	uint32_t pos=0;
	uint8_t protocolo_inferior=pila_protocolos[1];
	printf("modulo ICMP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);
	Parametros icmpdatos=*((Parametros*)parametros);

	/* Se rellena el campo tipo del paquete ICMP*/
	aux8=icmpdatos.tipo;
	memcpy(segmento+pos,&aux8,sizeof(uint8_t));
	pos+=sizeof(uint8_t);

	/* Se rellena el campo codigo  del paquete ICMP */
	aux8=icmpdatos.codigo;
	memcpy(segmento+pos,&aux8,sizeof(uint8_t));
	pos+=sizeof(uint8_t);

	/* Se rellena el campo codigo  del paquete ICMP */
	if(longitud%2 != 0){
		printf("El campo longitud del mensaje ICMP no es par");
		return -1;
	}
	if(calcularChecksum(mensaje, ICMP_HLEN+len(longitud), &aux8)){
		printf("Error al calcular el checksum de ICMP\n");
		return -1;
	}
	aux16 = (uint16_t) aux8;
	memcpy(segmento+pos, &aux16, sizeof(uint16_t));
	pos+=sizeof(uint16_t);

	/* Se rellena el campo identificador */
	aux16 = ID_ICMP;
	memcpy(segmento+pos, &aux16, sizeof(uint16_t));
	ID_ICMP += 1;
	pos+=sizeof(uint16_t);

	/* Se rellena el campo Numero de secuencia*/
	aux = NSEQ_ICMP;
	memcpy(segmento+pos, &aux16, sizeof(uint16_t));
	NSEQ_ICMP+=1;
	pos+=sizeof(uint16_t);

	/* Se rellena el campo datos */
	if(longitud > 48){
		print("El mensaje es de mas de 48 Bytes\n");			/*!!!!!!!!!!!!!!!!!!!!!!!!!PREGUNTAR SIE HACE FALTA Y SI ES ASI!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
		return -1;
	}
	memcpy(segmento+pos, mensaje, longitud*sizeof(uint8_t));
	pos+=longitud*sizeof(uint8_t);

	//Se llama al protocolo definido de nivel inferior a traves de los punteros registrados en la tabla de protocolos registrados
	return protocolos_registrados[protocolo_inferior](segmento,longitud+pos,pila_protocolos,parametros);
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
	uint16_t puerto_origen = 0, suma_control=0;
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

//TODO
//[...] 
//obtenerPuertoOrigen(...)
	aux16=htons(puerto_origen);
	memcpy(segmento+pos,&aux16,sizeof(uint16_t));
	pos+=sizeof(uint16_t);
	
//TODO Completar el segmento [...]
//[...] 
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
	uint32_t aux32;
	uint16_t aux16;
	uint8_t aux8;
	uint32_t pos=0,pos_control=0;
	uint8_t IP_origen[IP_ALEN];
	uint8_t protocolo_superior=pila_protocolos[0];
	uint8_t protocolo_inferior=pila_protocolos[2];
	pila_protocolos++;	/*Para apuntarlo a pila_protocolos[1]*/
	uint8_t mascara[IP_ALEN],IP_rango_origen[IP_ALEN],IP_rango_destino[IP_ALEN];

	printf("modulo IP(%"PRIu16") %s %d.\n",protocolo_inferior,__FILE__,__LINE__);

	Parametros ipdatos=*((Parametros*)parametros);
	uint8_t* IP_destino=ipdatos.IP_destino;

	/*Introducimos en el datagrama el campo version y IHL porque son 4 bits cada uno*/
	aux8 = 0b01000101;									/*!!!!!!!!!!!!!!!!!!!!!!!!!PREGUNTAR 5 O 6!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
	memcpy(datagrama+pos,&aux8,sizeof(uint8_t));
	pos+=sizeof(uint8_t);

	/*Introducimos en el datagrama el campo IHL*/
	/*Introducimos en el datagrama el campo Tipo Servicio*/
	/*Introducimos en el datagrama el campo Longitud Total*/
	/*Introducimos en el datagrama el campo Identificacion*/
	/*Introducimos en el datagrama el campo Flags*/
	/*Introducimos en el datagrama el campo Posicion*/
	/*Introducimos en el datagrama el campo Tiempo de vida*/
	/*Introducimos en el datagrama el campo */





//TODO
//Llamar a solicitudARP(...) adecuadamente y usar ETH_destino de la estructura parametros
//[...] 
//TODO A implementar el datagrama y fragmentación, asi como control de tamano segun bit DF
//[...] 
//llamada/s a protocolo de nivel inferior [...]


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
//TODO
//[....]
//[...] Variables del modulo
uint8_t trama[ETH_FRAME_MAX]={0};

printf("modulo ETH(fisica) %s %d.\n",__FILE__,__LINE__);	

//TODO
//[...] Control de tamano

//TODO
//[...] Cabecera del modulo

//TODO
//Enviar a capa fisica [...]  
//TODO
//Almacenamos la salida por cuestiones de debugging [...]
	
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
//TODO
//[...]
}


/***************************Funciones auxiliares implementadas**************************************/

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


