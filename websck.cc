# include <syslog.h>

#include <stdlib.h> 
#include <getopt.h> 
#include <stdarg.h> 

#include "websck.h"
#include "conf.h"

static int deny_deflate;
static int deny_mux;

int callback_authentication(struct libwebsocket_context * thi, struct libwebsocket *wsi, enum libwebsocket_callback_reasons reason, 
			void *user, void *in, size_t len) {
 
	// The 4096 number in the line bellow must be adjusted to the protocol I will design.
	//unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + 4096 + LWS_SEND_BUFFER_POST_PADDING];
	//int l;
	//int fifo;
	//char* my_buffer;
 
	switch (reason) { 
		case LWS_CALLBACK_CLOSED: 
			
			g_message("LWS_CALLBACK_CLOSED"); 
						
			/* Entre otras cosas aquí tengo que inicializar el contador wsk_keep_alive para que cuando se
			 haya pasado ese tiempo el programa vuelva a establecer el websocket con el servidor.
			 */
 
			break; 

		case LWS_CALLBACK_CLIENT_RECEIVE:
			
			wsk_comm_interface->reception_queu->receive_frame((char *)in,len);

			break;

		case LWS_CALLBACK_CLIENT_ESTABLISHED:

			/* This is the first time the wsck is stablished, so we should send something to the server.
			Is is a good time to call an initialization function that checks if this is the very first
			time we connect to the server (after bootup) to send the apropiate registration information.
			If not then we will see what to do depending on the reason the wsck was stablished for.
		 	*/
		 	
		 	libwebsocket_callback_on_writable(thi, wsi);
			break;

		case LWS_CALLBACK_CLIENT_WRITEABLE:

			wsk_comm_interface->sender_queu->run(wsi);
			
			/*
		 	* without at least this delay, we choke the browser
		 	* and the connection stalls, despite we now take care about
		 	* flow control
		 	*/
				
			/*I really need to see if this is important, because I don't want to waste 200 ms*/

			usleep(200);
			

			/* get notified as soon as we can write again */

			libwebsocket_callback_on_writable(thi, wsi);
			
			break;

		/*Here I must analyse what other "reasons" are important for my protocol in order to implement
		their handles.*/

		/* because we are protocols[0] ... */ 

		case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:
			if ((strcmp((char*)in, "deflate-stream") == 0) && deny_deflate) {
				 fprintf(stderr, "denied deflate-stream extension\n"); 
				return 1;
			}
			if ((strcmp((char*)in, "x-google-mux") == 0) && deny_mux) { 
				fprintf(stderr, "denied x-google-mux extension\n");
				return 1;
			} 
			break; 
		default: 
			break; 
	}

	return 0;
}

struct libwebsocket_context* wsk_create_context(void){
	
	struct lws_context_creation_info* context_creation_info;
	struct libwebsocket_context* contx = NULL;
	
	//struct libwebsocket_protocols* ptr_protocols = gnew0(struct libwebsocket_protocols, 1);
	
	//context_creation_info = g_try_new0(struct_type, n_structs);	//Esto es lo que debo usar en la versión final 
																	//pues la versión de abajo aborta el programa en un error
	context_creation_info = g_new0(struct lws_context_creation_info, 1);

	context_creation_info->port = CONTEXT_PORT_NO_LISTEN;
	context_creation_info->iface = CONF("wsk_iface");
	context_creation_info->protocols = protocols;
	context_creation_info->extensions = NULL; //Chequear bien por qué en el código original aparece: libwebsocket_internal_extensions
	context_creation_info->ssl_cert_filepath = NULL;
	context_creation_info->ssl_private_key_filepath =  NULL;
	context_creation_info->ssl_ca_filepath =  NULL;
	context_creation_info->ssl_cipher_list =  NULL;
	context_creation_info->gid = -1;
	context_creation_info->uid = -1;
	context_creation_info->options = 0;
	context_creation_info->user = NULL;
	context_creation_info->ka_time = 0;
	context_creation_info->ka_probes = 0;
	context_creation_info->ka_interval = 0;

	contx = libwebsocket_create_context(context_creation_info);
	if (context_creation_info != NULL) g_free(context_creation_info);
	return contx;
	
}

struct libwebsocket* wsk_client_connect (struct libwebsocket_context* context, time_t* connection_time){
	
	struct libwebsocket* wsi = NULL;
	
	// Here there must be selected from the configuration file (nocat.conf), or from the structure nocat_conf, the right value
	// of the variable wsk_server_address based in an specific algorithm. The objetive is to stablish a redundant infrastructure
	// of servers for connect. When that is done the second parameter of libwebsocket_client_connect should change and the whole
	// instruction should be inserted inside a loop that change that parameter until the connection is made. This mecanism should
	// have a timeout.
	
	//wsi_dumb = libwebsocket_client_connect(context, wsk_server_address, wsk_server_port, CONFd("wsk_use_ssl"), CONF("wsk_path_on_server"),
	//			CONF("wsk_server_hostname"), CONF("wsk_origin_name"), protocols[CONFd("wsk_protocol")].name, CONFd("ietf_version"));


	//Revisar las variables wsk_server_hostname y wsk_origin_name de la línea de arriba para poder 
	//parametrizar a full la llamada a libwebsocket_client_connect.
	
	wsi = libwebsocket_client_connect(context, CONF("wsk_server_address"), CONFd("wsk_server_port"),
				 CONFd("wsk_use_ssl"), CONF("wsk_path_on_server"),
				 "","", protocols[CONFd("wsk_protocol")].name, CONFd("ietf_version"));
	
	*connection_time = time(NULL);
	
	return wsi;
		
}
