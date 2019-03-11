//#include "websck.h"
# include "gateway.h"
# include <netdb.h>

extern GHashTable* peer_tab;
extern GHashTable *nocat_conf;
extern class comm_interface* wsk_comm_interface;
extern gchar* macAddressFrom;
extern class DNS_resolver* resolver;

void print_wsk_server_name(struct respuesta* resp,void* user_data){
	
	if (resp->nombres[0] != NULL) g_debug("print_wsk_server_name: name of the wsk server: %s",resp->nombres[0]);
	else g_debug("print_wsk_server_name: respuesta vacia");
}

void set_wsk_server_IP(struct respuesta* resp,void* user_data){
	
	if (resp->ip_addresses[0] != NULL) {
		
		int x;
		
		g_free(wsk_comm_interface->wsk_server_IP);
		wsk_comm_interface->wsk_server_IP = g_new0(char,INET_ADDRSTRLEN);
		
		// Aqu'i tengo que garantizar primero que resp->ip_addresses[0] no sea vacio
		
		inet_ntop( AF_INET, &(resp->ip_addresses[0]->sin_addr), wsk_comm_interface->wsk_server_IP, INET_ADDRSTRLEN );
		g_debug("set_wsk_server_IP: direccion IP del servidor websockets: %s",wsk_comm_interface->wsk_server_IP);
		
		//resolver->solve_name((unsigned char*)"10.0.55.200.in-addr.arpa",print_wsk_server_name,NULL);
		
		x =  wsk_comm_interface->wsk_create();
		if (x == -1){
				
			g_warning("set_wsk_server_IP: websocket initialization error, retrying...");
			wsk_comm_interface->wsk_set_status(WSK_DISCONNECTED,"set_wsk_server_IP");
		}
	}
	else wsk_comm_interface->wsk_set_status(WSK_DISCONNECTED,"set_wsk_server_IP");
	return;
}

gboolean is_IP(gchar* name){
	
	unsigned int res;
	struct sockaddr_in addr;
	//struct sockaddr_in6 addr6;
	
	res = inet_pton(AF_INET, name, &(addr.sin_addr));
	//res = inet_pton(AF_INET6, name, &(addr6.sin6_addr));
	
	if (res == 1) return TRUE;
	else return FALSE;
}

int callback_authentication(struct libwebsocket_context* thi, struct libwebsocket* wsi, enum libwebsocket_callback_reasons reason, 
			void *user, void *in, size_t len) {
 	
	switch (reason) {
		
		case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
			
			g_warning("wsk callback_authentication: LWS_CALLBACK_CLIENT_CONNECTION_ERROR");
			
			wsk_comm_interface->wsk_set_status(WSK_ERROR,"callback_authentication");
			
			break;
			
		case LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH:
		
			g_debug("wsk callback_authentication: LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH");
			break;

		case LWS_CALLBACK_CLIENT_ESTABLISHED:

		 	g_debug("wsk callback_authentication: LWS_CALLBACK_CLIENT_ESTABLISHED");
			
			wsk_comm_interface->clear_init();
			wsk_comm_interface->wsk_set_status(WSK_CLIENT_ESTABLISHED,"callback_authentication");
		 	
			break;
			
		case LWS_CALLBACK_CLOSED:
			 
			g_debug("wsk callback_authentication: LWS_CALLBACK_CLOSED");
						
			wsk_comm_interface->wsk_set_status(WSK_CLOSED,"callback_authentication");
			return -1;
 
			break; 

		case LWS_CALLBACK_CLIENT_RECEIVE:
			
			g_debug("wsk callback_authentication: LWS_CLIENT_RECEIVE");
			//g_debug("recibidos %d  bytes",len);
			//g_message("recibidos %d  bytes",len);
			//g_message("recibido: %s",(char*)in);
			
			//if (libwebsocket_is_final_fragment(wsi)) g_message("la trama llegó completa");
			
			//int x;
			//x = strlen((char*)in);
			
			//g_message("contados: %d caracteres",x);
			
			wsk_comm_interface->reception_queu->receive_frame((char *)in,len);

			break;

		case LWS_CALLBACK_CLIENT_RECEIVE_PONG:
		
			g_debug("wsk callback_authentication: LWS_CALLBACK_CLIENT_RECEIVE_PONG");
					
			break;
			
		case LWS_CALLBACK_CLIENT_WRITEABLE:
			
			if (wsk_comm_interface->get_status() == WSK_IDDLE){
				 
				 g_message("wsk callback_authentication: Begining wsk close secuence..");
				 return -1;
			}
			
			g_debug("wsk callback_authentication: LWS_CLIENT_WRITEABLE");
			
			wsk_comm_interface->sender_queu->run(wsi,wsk_comm_interface->get_status());
			
			/*
		 	* without at least this delay, we choke the browser
		 	* and the connection stalls, despite we now take care about
		 	* flow control
		 	
				
			I really need to see if this is important, because I don't want to waste 200 ms*/

			//usleep(200);
			
			//g_message("Se esperó con éxito");
			/* get notified as soon as we can write again*/

			//libwebsocket_callback_on_writable(thi, wsi);
			
			//g_message("Se reregistró con éxito");
			
			break;
		
		case LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS:
		
			g_debug("wsk callback_authentication: LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS");
			break;
			
		case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		
			g_debug("wsk callback_authentication: LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER");
 			break;
 			
 		/* because we are protocols[0] ...  */

		case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:
		
			g_debug("wsk callback_authentication: LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED");
			/*
			if ((strcmp((char*)in, "deflate-stream") == 0) && deny_deflate) {
				 g_message("denied deflate-stream extension\n"); 
				return 1;
			}
			if ((strcmp((char*)in, "deflate-frame") == 0) && deny_deflate) {
				g_message("denied deflate-frame extension\n");
				return 1;
			}
			if ((strcmp((char*)in, "x-google-mux") == 0) && deny_mux) { 
				g_message("denied x-google-mux extension\n");
				return 1;
			}*/
			
			return 1; // Por el momento no pienso soportar ninguna extensión.
			break;
			
		case LWS_CALLBACK_PROTOCOL_INIT:
		
			g_debug("wsk callback_authentication: LWS_CALLBACK_PROTOCOL_INIT");
 			break;

 		case LWS_CALLBACK_ADD_POLL_FD:
 		
 			g_debug("wsk callback_authentication: LWS_CALLBACK_ADD_POLL_FD");
 			break;
 			
		case LWS_CALLBACK_DEL_POLL_FD:
		
 			g_debug("wsk callback_authentication: LWS_CALLBACK_DEL_POLL_FD");
 			break;
 			
 		case LWS_CALLBACK_SET_MODE_POLL_FD:
 		
 			g_debug("wsk callback_authentication: LWS_CALLBACK_SET_MODE_POLL_FD");
 			break;
 			
		case LWS_CALLBACK_CLEAR_MODE_POLL_FD:
		
			g_debug("wsk callback_authentication: LWS_CALLBACK_CLEAR_MODE_POLL_FD");
			break;
			
		case LWS_CALLBACK_PROTOCOL_DESTROY:
		
			g_debug("wsk callback_authentication: LWS_CALLBACK_PROTOCOL_DESTROY");
			wsk_comm_interface->wsk_set_status(WSK_DISCONNECTED,"callback_authentication");
			break;
				
		default:
		
			g_message("wsk callback_authentication: Libwebsocket callback function called with unnatended reason (%d)",(int)reason);

			break; 
	}
	
	return 0;
}

gboolean call_libwebsocket_service(void* dummy){
	
	switch (wsk_comm_interface->get_status()){
		
		case WSK_WAITING_CONFIRM:
		
			// Aquí tengo que incluir un contador para un timeout, en caso de que se cumpla el timeout
			// avisar a la administración del sistema del error, poner init en TRUE y poner el wsk en 
			// estado WSK_CLOSED para que vuelva a intentar conectarse dentro de un segundo.

			break;
			
		case WSK_ERROR:
		
			// La misma historia que el estado anterior, poner init en TRUE para que cuando wsk_comm_interface->reset
			// ponga el wsk en estado DISCONNECTED y se vuelva a entrar en esta función no haya que esperar el tiempo
			// wsk_keep_alive para volver a intentar la conexión. También tengo que avisar a la administración del 
			// error.
			
			wsk_comm_interface->set_init();
			wsk_comm_interface->reset();
			break;
			
		case WSK_CLOSED:
			
			wsk_comm_interface->reset();
			break;
			
		case WSK_CLIENT_ESTABLISHED:
		
			if ((g_hash_table_size(peer_tab) == 0) && 
				(wsk_comm_interface->sender_queu->get_count() == 0)){
			
				if (difftime(time(NULL),wsk_comm_interface->get_last_access_time())
					 > wsk_comm_interface->get_wsk_time_out()){
						
					 wsk_comm_interface->wsk_set_status(WSK_IDDLE,"call_libwebsocket_service");
					 libwebsocket_callback_on_writable(wsk_comm_interface->get_context(),
														wsk_comm_interface->get_wsi());
				}
			}
			else wsk_comm_interface->set_last_access_time();
			break;
			
		case WSK_DISCONNECTED:
		
			if (!(wsk_comm_interface->is_init())){
				
				if (difftime(time(NULL),wsk_comm_interface->get_last_access_time())
				 < wsk_comm_interface->get_wsk_keep_alive()) {
					
					return TRUE;	
				}
			}
			
			wsk_comm_interface->wsk_initialize();
			
			return TRUE;
		
		case WSK_WAITING_DNS:

			return TRUE;
		
		default:
			break;
		
	}
	
	libwebsocket_service(wsk_comm_interface->get_context(),0);

	return TRUE;
		
}

unsigned int extract_value (const char* token,char* begin,bool* corre){

	unsigned int resultado = 0;
	char* tempo;
	*corre = FALSE;
	
	char* ptr_begin = strstr(begin, token);
	if (ptr_begin != NULL){
		
		ptr_begin = ptr_begin + strlen(token);
		char* ptr_end = strchr(ptr_begin,'\"');
		if (ptr_end != NULL){
			
			tempo = (char*)calloc(1,ptr_end - ptr_begin + 1);
			memcpy(tempo,ptr_begin,ptr_end - ptr_begin);
		 }
		else return 0; 
		resultado = (unsigned int) strtol(tempo,NULL,0);
		free(tempo);
		*corre = TRUE;
	}
	return resultado;
}

char* extract_value_s (const char* token,char* begin,bool* corre){
	
	char* resultado = NULL;
	*corre = FALSE;
	
	char* ptr_begin = strstr(begin, token);
	if (ptr_begin != NULL){
		
		ptr_begin = ptr_begin + strlen(token);
		char* ptr_end = strchr(ptr_begin,'\"');
		if (ptr_end != NULL){
			
			resultado = (char*)calloc(1,ptr_end - ptr_begin + 1);
			memcpy(resultado,ptr_begin,ptr_end - ptr_begin);
		}
		else return resultado;
		*corre = TRUE;
	}
	return resultado;
}

void parse_status(int status, char* status_char){
	
	switch (status) {
		
		case 0:
		
			strcpy(status_char,(char*)"WSK_DISCONNECTED");
			break;
		
		case 1:
		
			strcpy(status_char,(char*)"WSK_WAITING_DNS");
			break;
			
		case 2:
		
			strcpy(status_char,(char*)"WSK_WAITING_CONFIRM");
			break;

		case 3:
		
			strcpy(status_char,(char*)"WSK_CLIENT_ESTABLISHED");
			break;
			
		case 4:
		
			strcpy(status_char,(char*)"WSK_ERROR");
			break;
			
		case 5:
		
			strcpy(status_char,(char*)"WSK_CLOSED");
			break;
			
		case 6:
		
			strcpy(status_char,(char*)"WSK_IDDLE");
			break;
			
		default:
		
			strcpy(status_char,(char*)"WSK_UNKNOW");
			break;
	}
}

/***************************** class m_frame methods *******************************/
#ifdef MFRAME

// class m_frame constructor from a message (parse an arrived xml message to a class m_frame)

/*
 
<Protocol Version="0">
	<Frame Type="1" Command="6" FrameCount="1" AckCount="0" BodyFrameSize="0" FromDeviceId="xxx" ToDeviceId="yyy">
		<Parameters Count="1">
			<Parameter Name="IsAuthenticated" Value="true" />
			<Parameter Name="UserToken" Value="48e3f2d3-f805-4ea7-afda-d0fe2344b0b3" />
		</Parameters>
	</Frame>
</Protocol>

*/

m_frame::m_frame(char* message, unsigned int m_size, bool* correct){
	
	char* message_remaining = message;
	*correct = FALSE;
	
	//Chequear que el encabezamiento y el terminador xml estén en su sitio.
	
	if ((memcmp ("<Protocol", message, 9) != 0) || (strstr (message, "</Protocol>") == NULL)) return;
	
	// Buscar el terminador del protocol header, poner un caracter nulo en él y marcar el
	// próximo caracter como donde vamos a seguir después de parsear el protocolo.
	
	char* protocol_header_end = strchr(message_remaining, '>');
	if (protocol_header_end != NULL){
		
		memcpy(protocol_header_end,"\0",1);
		message_remaining = protocol_header_end + 1;
	}
	// Buscar el valor del parámetro Version.
	
	Version = extract_value ("Version=\"",message + 8,correct);
	if (!(*correct)) return; 
	
	*correct = FALSE;
	
	// Procesamiento de la información de la trama.
	
	char* frame_header_begin = strstr (message_remaining, "<Frame ");
	if (frame_header_begin == NULL) return;
	
	frame_header_begin = frame_header_begin + 7;
	char* frame_header_end = strchr (frame_header_begin,'>');
	if (frame_header_end != NULL){
		
		memcpy(frame_header_end,"\0",1);
		
		if (memcmp((frame_header_end-1),"/",1) == 0) message_remaining = NULL; 
		else message_remaining = frame_header_end + 1;
	}
	else return;
	
	Type = extract_value ("Type=\"",frame_header_begin,correct);
	if (!(*correct)) return; 
	
	Command = extract_value ("Command=\"",frame_header_begin,correct);
	if (!(*correct)) return;
	
	FrameCount = extract_value ("FrameCount=\"",frame_header_begin,correct);
	if (!(*correct)) return;
	
	AckCount = extract_value ("AckCount=\"",frame_header_begin,correct);
	if (!(*correct)) return;
	
	BodyFrameSize = extract_value ("BodyFrameSize=\"",frame_header_begin,correct);
	if (!(*correct)) return;
	
	if (message_remaining == NULL){
		
		*correct = TRUE;
		return;
	}
	else {
		
		// Procesamiento de los parámetros.
		*correct = FALSE;
		char* parameters_header_begin = strstr (message_remaining, "<Parameters ");
		if (parameters_header_begin == NULL) return;
		
		parameters_header_begin = parameters_header_begin + 12;
		
		char* parameters_header_end = strchr (parameters_header_begin,'>');
		if (parameters_header_end != NULL){
			
			memcpy(parameters_header_end,"\0",1);
			message_remaining = parameters_header_end + 1;
			parameters = g_new0(struct params,1);
		}
		else return;
		
		parameters->cantidad = extract_value ("Count=\"",parameters_header_begin,correct);
		if (!(*correct)) return;
		
		parameters->items = g_new0(item*,parameters->cantidad);
		
		char *parameter_header_begin, *parameter_header_end;
		
		for (unsigned int i = 0;i<parameters->cantidad;i++){
			
			parameters->items[i] = g_new0(struct item,1);
			
			parameter_header_begin = strstr (message_remaining, "<Parameter ");
			
			if (parameter_header_begin == NULL) return;
			parameter_header_begin = parameter_header_begin + 11;
			parameter_header_end = strchr (parameter_header_begin,'>');
			if (parameter_header_end != NULL){
				
				memcpy(parameter_header_end,"\0",1);
				message_remaining = parameter_header_end + 1;
			}
			
			parameters->items[i]->nombre = extract_value_s("Name=\"",parameter_header_begin,correct);
			if (!(*correct)) return;
			
			parameters->items[i]->valor = extract_value_s("Value=\"",parameter_header_begin,correct);
			if (!(*correct)) return;
		}
	}
	*correct = TRUE;
}

/* class m_frame constructor from fields (build a class m_frame given certain fields)
m_frame::m_frame(char* comando, struct params* parameters_in, struct data* datos_in, bool* correct) {

	m_frame_index = 0;
	m_frame_index_ack = 0;

	command_name = comando;
	parameters = NULL;
	datos = NULL;
	readed = false;
	m_frame_as_message = NULL;
	memset (frame_type,0,2);

	// Este bloque if else de abajo tengo que cambiarlo por un mecanismo mejor y más parametrizable para establecer el tipo de
	// trama a partir del nombre del comando.

	if ((strcmp(comando,"INIT") == 0) || (strcmp(comando,"GETPARAMS") == 0) || (strcmp(comando,"LISTPARAMS") == 0)
		|| (strcmp(comando,"LISTPARAM") == 0) || (strcmp(comando,"CHANGEPARAM") == 0) || (strcmp(comando," CHANGEPARAMPERS") == 0)
		|| (strcmp(comando,"ADDPARAM") == 0) || (strcmp(comando," ADDPARAMPER") == 0) || (strcmp(comando,"REMPARAM") == 0)
		|| (strcmp(comando,"REMPARAMPERS") == 0) || (strcmp(comando,"SAVESTATUSCLIENT") == 0) || (strcmp(comando," SAVESTATUSOK") == 0)
		|| (strcmp(comando,"SAVESTATUSCLIENT") == 0) || (strcmp(comando,"GETSTATUSCLIENTS") == 0) || (strcmp(comando,"STATUSCLIENTS") == 0)
		|| (strcmp(comando,"STATUSCLIENT") == 0) || (strcmp(comando,"CLEARSTATUSCLIENTS") == 0) || (strcmp(comando,"HAVESTATUS") == 0)
		|| (strcmp(comando,"VER") == 0) || (strcmp(comando,"ACTUALIZAR") == 0) || (strcmp(comando,"GETARCHIVO") == 0)
		|| (strcmp(comando,"SETARCHIVO") == 0) || (strcmp(comando,"AUTH") == 0)){

		memcpy(frame_type,"C",1);
	}
	else if (strcmp(comando,"ARCHIVO") == 0){

		memcpy(frame_type,"D",1);
	}
	else if (strcmp(comando,"ACKNOWLEDGE") == 0){
		
		memcpy(frame_type,"A",1);
		body_size = 0;
		*correct = true;
		//print();
		return;
	}
	else{

		lwsl_err("comando no soportado: %s",comando);

		// Aquí tengo que eliminar los buffers comando, parameters_in y data_in que me pasaron en la llamada de la función pues
		// ya no van a seguir haciendo falta ya que el comando es incorrecto ?

		*correct = false;
		return;
	}
	unsigned int parameters_size = 0;

	if (parameters_in != NULL){

		parameters = parameters_in;

		for (unsigned int i = 0; i < parameters->cantidad;i++){

			parameters_size = parameters_size + strlen(parameters->values[i]) + 1;
			//g_message("parameter %d size = %d",i,parameters_size);

		}
	//g_message("total parameters_size = %d",parameters_size);

	}
	body_size = strlen(comando) + parameters_size ;

	if (datos_in != NULL){

		datos = datos_in;
		body_size = body_size + datos->size + 1;
	}
	//g_message("body_size = %d",body_size);
	if (body_size > 4075){

		lwsl_err("frame maximum size exceded (%d)",body_size);
		*correct = false;
	}
	else *correct = true;
	//print();
	return;
}*/

//class m_frame destructor
m_frame::~m_frame(){

	//g_message("entré al destructor de m_frames");
	//g_message("nombre del comando a destruir: %s",command_name);
	
	if (parameters != NULL){
		
		for (unsigned int i=0; i<parameters->cantidad;i++){
			
			if (parameters->items[i] != NULL){
				
				if (parameters->items[i]->nombre != NULL) free(parameters->items[i]->nombre);
				if (parameters->items[i]->valor != NULL) free(parameters->items[i]->valor);
				free(parameters->items[i]);
			}
		}
		free(parameters);
	}
}

unsigned short int m_frame::get_index(){

	return FrameCount;
}

/*
unsigned short int m_frame::get_index_ack(){

	return m_frame_index_ack;
}

bool m_frame::mark_readed(){

	readed = true;
	return readed;
}

bool m_frame::is_readed(){

	return readed;
}

unsigned short int m_frame::get_body_size(){

	return body_size;
}

char* m_frame::get_frame_type(){

	return frame_type;
}

char* m_frame::get_command_name(){

	return command_name;
}

struct params* m_frame::get_parameters(){

	return parameters;
}

struct data* m_frame::get_data(){

	return datos;
}

unsigned char* m_frame::as_message(){
	
	unsigned char* buffer;
	unsigned char* new_pos;
	
	if (m_frame_as_message != NULL) return m_frame_as_message;
	
	else {
		
		buffer = (unsigned char*)g_malloc0(21 + body_size);
		m_frame_as_message = buffer;
	}
	
	g_memmove(buffer,"_###_",5);
	g_memmove(buffer+5,&m_frame_index,2);
	g_memmove(buffer+7,"_",1);
	g_memmove(buffer+8,&m_frame_index_ack,2);
	g_memmove(buffer+10,"_",1);
	g_memmove(buffer+11,&body_size,2);
	g_memmove(buffer+13,"_",1);
	g_memmove(buffer+14,&frame_type,1);
	
	if (memcmp (&frame_type, "A", 1) != 0){
	
		g_memmove(buffer+15,"_",1);
		g_memmove(buffer+16,command_name,strlen(command_name));
		new_pos = buffer + 16 + strlen(command_name);
		if (parameters != NULL){

			for (unsigned int i = 0;i < parameters->cantidad;i++){

				g_memmove(new_pos,"_",1);
				new_pos = new_pos +1;
				g_memmove(new_pos,parameters->values[i],strlen(parameters->values[i]));
				new_pos = new_pos + strlen(parameters->values[i]);
			}
		}
		if (datos != NULL){

			g_memmove(new_pos,":",1);
			new_pos = new_pos +1;
			g_memmove(new_pos,datos->binaries,datos->size);
			new_pos = new_pos + datos->size;
			
		}
	}
	else new_pos = buffer + 15;
	
	g_memmove(new_pos,"_###_",5);
	
	
	
	return buffer;
}

char* m_frame::print(){
	
	//char cabeza[body_size+30];
	char* cabeza = (char*)g_malloc0(body_size+30);
	//memset (cabeza,0,body_size+30);
	sprintf(cabeza,"_###_%d_%d_%d_%s",m_frame_index,m_frame_index_ack,body_size,frame_type);
	
	if (body_size > 0){
		
		char cuerpo[body_size];
		memset (cuerpo,0,body_size);
		
		if ( (memcmp(frame_type,"C",1) == 0) || (memcmp(frame_type,"D",1) == 0) ){
			
			strcat (cuerpo,"_");
			strcat (cuerpo,command_name);
			
			if (parameters != NULL){
				
				for (unsigned int i = 0;i < parameters->cantidad;i++){
					strcat (cuerpo,"_");
					strcat (cuerpo,parameters->values[i]);
				}
			}
			if (datos != NULL){
				
				strcat (cuerpo,":");
				char dada[10];
				memset(dada,0,10);
				sprintf(dada,"%d",datos->size);
				strcat (cuerpo,dada);
				strcat (cuerpo,"b");
			}
		}
		strcat(cabeza,cuerpo);
	}
	strcat(cabeza,"_###_");
	//g_message(cabeza);
	return cabeza;
}*/

#endif
/***************************** end class m_frame methods ***************************/



/***************************** class received_messages_queu methods ****************/
#ifdef MFRAME

// Constructor
received_messages_queu::received_messages_queu(){

	ptr_frames = NULL;
	count = 0;

}

// Destructor

received_messages_queu::~received_messages_queu(){

	return;
}

// Receptor de tramas

bool received_messages_queu::receive_frame(char* message,size_t message_size){

	bool right = false;

	// Crear una clase m_frame con los datos que llegaron en la transmisión.
	//g_message("recibiendo una trama");
	class m_frame* temp_frame = new m_frame((char*) message, message_size, &right);

	if (!right){	// Si hubo algún problema en la creación de la clase m_frame eliminarla y retornar false.
	
		lwsl_warn("received_messages_queu::receive_frame: trama incorrecta..");
		
		char* tem = (char*)g_malloc0(message_size + 2);
		memcpy(tem,message,message_size);
		g_debug(tem);
		g_free(tem);
		delete temp_frame;
		return false;
	}
	else g_debug("received_messages_queu::receive_frame: se recibió la trama de autorización de cliente correctamente..");
	
	// Aquí chequeo si es una trama ack, en caso de serlo por el momento solamente se descarta esta y ya.
	// En un futuro se deberá chequear en la cola de salida la trama que está esperando por el ack, se elimina de la
	// cola de salida (tomando las medidas extras necesarias como resetear contadores de espera para reenvío, etc) y 
	// se elimina la trama ack recientemente llegada.
	
	/*	Bloque comentariado temporalmente.
	
	if (memcmp(temp_frame->get_frame_type(),"A",1) == 0){
		g_message("recibido un ack");
		delete temp_frame;
		wsk_comm_interface->set_last_access_time();
		return true;
	}*/
	
	// Chequear que no haya otra trama en la cola que tenga el mismo index, de ser así eliminar la trama
	// llegada y retornar false.

	for (int i = 0;i<count;i++){

		if (ptr_frames[i]->get_index() == temp_frame->get_index()){

			lwsl_warn("received_messages_queu::receive_frame: repeated frame arrived, descarted...");
			delete temp_frame;
			return false;
		}
	}

	// Poner la trama en el final de la cola de tramas llegadas.
	struct m_frame** temp = (struct m_frame**) g_malloc0(count + 1);

	for (int i=0;i<count;i++){

		temp[i] = ptr_frames[i];
	}
	if (ptr_frames != NULL) g_free(ptr_frames);
	ptr_frames = temp;
	ptr_frames[count] = temp_frame;

	count++;
	wsk_comm_interface->set_last_access_time();
	
	if (temp_frame->Command == 6){
		
		if (temp_frame->parameters != NULL){
			
			if (temp_frame->parameters->cantidad == 2){
				
				if ((temp_frame->parameters->items[0]->nombre != NULL) &&
					(temp_frame->parameters->items[0]->valor != NULL) &&
					(temp_frame->parameters->items[1]->nombre != NULL) &&
					(temp_frame->parameters->items[1]->valor != NULL)) {
					
					if ((strcmp(temp_frame->parameters->items[0]->nombre,"IsAuthenticated") == 0) &&
						(strcmp(temp_frame->parameters->items[1]->nombre,"UserToken") == 0)){
						
						g_idle_add((GSourceFunc)check_peer, temp_frame);
					}
				}
			}
		}
	}
	
	// Aquí tengo que chequear si la trama requiere una respuesta concreta, si no
	// extraer el index de la trama que me enviaron y responder con un ack. Responder con un ack
	// significa crear una trama ack y adicionarla a la cola de salida.
	
	return true;
}

// Eliminador de trama (como parámetro se le entra el index de envío)

bool received_messages_queu::delete_frame(unsigned int m_frame_index){

	for (int i = 0;i<count;i++){
		 
		if (ptr_frames[i]->get_index() == m_frame_index){

			delete ptr_frames[i];

			struct m_frame** temp = (struct m_frame**) g_malloc0(count-1);

			if (temp != NULL){ 	// Si temp == NULL es porque count - 1 = 0, es decir i = 0 y la trama que se eliminó
								// era la única que había.

				for (int a = 0;a < i;a++){

					temp[a] = ptr_frames[a];
				}
				for (int a = i;a < count - 1;a++){

					temp[a] = ptr_frames[a+1];
				}
				g_free(ptr_frames);
				ptr_frames = temp;
			}
			count--;

			if (count == 0){

				g_free(ptr_frames);
				ptr_frames = NULL;
			}

			return true;
		}
	}
	return false;
}

#endif
/***************************** end class received_messages_queu methods ************/



/***************************** class send_messages_queu methods ********************/
#ifdef MFRAME

// Constructor

send_messages_queu::send_messages_queu(){

	ptr_frames = NULL;
	count = 0;


	return;
}

// Destructor
send_messages_queu::~send_messages_queu(){

	return;
}

// Receptor de tramas

bool send_messages_queu::add_frame(char* comando, struct params* parameters_in, struct data* datos_in){

	//bool right = false;

	// Crear una clase m_frame con la información que se quiere transmitir.
	
	/* Bloque comentariado temporalmente.
	class m_frame* temp_frame = new m_frame(comando,parameters_in,datos_in, &right);
	
	
	if (!right){	// Si hubo algún problema en la creación de la clase m_frame eliminarla y retornar false.
		delete temp_frame;
		return false;
	}*/

	// Chequear que no haya otra trama en la cola que tenga el mismo index, de ser así eliminar la trama
	// llegada y retornar false.

	/*if (ptr_frames != NULL){

		for (int i = 0;i<count;i++){

			if (ptr_frames[i]->get_index() == temp_frame->get_index()){

				g_message("repeated frame (frame_index = %d), descarted...",temp_frame->get_index());
				delete temp_frame;
				return false;
			}
		}
	}*/

	// Poner la trama en el final de la cola de tramas por enviar.
	struct m_frame** temp = (struct m_frame**) g_malloc0(count + 1);

	if (ptr_frames != NULL){
		for (int i=0;i<count;i++){

			temp[i] = ptr_frames[i];
		}
		g_free(ptr_frames);
	}

	ptr_frames = temp;
	//ptr_frames[count] = temp_frame;
	count++;
	//char* dd = ptr_frames[count]->get_command_name();
	//g_message(dd);
	return true;
}


void send_messages_queu::run(struct libwebsocket *wsi,enum STATUSES wsk_status){

	//g_message("running send messages queu");
	unsigned int message_size;

	if (wsk_status == WSK_CLIENT_ESTABLISHED){
		
		if (ptr_frames != NULL){
			if (ptr_frames[0] != NULL){	// Hay algo que enviar
			
				/* Bloque comentariado temporalmente
				if (memcmp(ptr_frames[0]->get_frame_type(),"A",1) == 0) message_size = 20;
				else message_size = 21 + (ptr_frames[0]->get_body_size());*/
				
				unsigned char buffer[LWS_SEND_BUFFER_PRE_PADDING + message_size + LWS_SEND_BUFFER_POST_PADDING];
				
				// _###_00_00_00_C_LISTPARAMS_15_abcd_efgh:1234567890_###_
				// _###_00_00_00_C_INIT_###_      25 caracteres
				//g_message ("creando el mensaje desde la m_frame");
				
				/* Bloque comentariado temporalmente
				memcpy(&(buffer[LWS_SEND_BUFFER_PRE_PADDING]),ptr_frames[0]->as_message(),message_size);
				*/
				
				//g_message ("voy a enviar");
				int result = libwebsocket_write(wsi,
							&buffer[LWS_SEND_BUFFER_PRE_PADDING], message_size, LWS_WRITE_BINARY);

				//g_message("enviados = %d",result);
				//g_message("%d",ptr_frames[0]->get_body_size());

				if (result == (int)message_size){

					//tempo = ptr_frames[0]->get_index();
					//g_debug("send_messages_queu::run: enviada la trama: %s",ptr_frames[0]->print());
					/*	Bloque comentariado temporalmente
					delete_frame(ptr_frames[0]->get_index());
					*/
					wsk_comm_interface->set_last_access_time();
				}
				else if (result == -1){

				// aquí tengo que ver bien que hago pues esto es un error grave que según la documentación requiere
				// cerrar la conexión.
				}
			}
		}
	}
}

// Eliminador de trama (como parámetro se le entra el index de envío)
bool send_messages_queu::delete_frame(unsigned int m_frame_index){

	//g_message("entré en delete_frame");
	//g_message("count = %d",count);
	for (int i = 0;i<count;i++){

		/*	Bloque comentariado temporalmente
		if (ptr_frames[i]->get_index() == m_frame_index){

			//g_message("ptr_frames[i]->get_index() = %d",ptr_frames[i]->get_index());
			//g_message("m_frame_index = %d",m_frame_index);

			delete ptr_frames[i];

			//if (ptr_frames == NULL) g_message("ups");

			//g_message("borré la ptr_frame");

			struct m_frame** temp = (struct m_frame**) g_malloc0(count-1);

			if (temp != NULL){ 	// Si temp == NULL es porque count - 1 = 0, es decir i = 0 y la trama que se eliminó
								// era la única que había.
				//g_message("xxx");

				for (int a = 0;a < i;a++){

					temp[a] = ptr_frames[a];
				}
				for (int a = i;a < count - 1;a++){

					temp[a] = ptr_frames[a+1];
				}
				g_free(ptr_frames);
				ptr_frames = temp;
			}
			count--;
			//g_message("count despues = %d",count);
			if (count == 0){

				g_free(ptr_frames);
				ptr_frames = NULL;
			}

			return true;
		}*/
	}
	return false;
}

unsigned short int send_messages_queu::get_count(){
	
	return count;
}

#endif
/***************************** end class send_messages_queu methods ****************/



/***************************** class wsk_comm_interface methods ********************/
#ifdef MFRAME

// constructor
comm_interface::comm_interface(){

	lws_set_log_level(CONFd("wsk_log_level"), lwsl_emit_syslog);
	
	context = NULL;
	wsk_time_out = CONFd("wsk_time_out");
	wsk_keep_alive = CONFd("wsk_keep_alive");
	
	wsi = NULL;
	
	wsk_server_IP = NULL;
	
	reception_queu = new class received_messages_queu;
	sender_queu = new class send_messages_queu;
	
	//service = &comm_interface::call_libwebsocket_service;
	//callback = &comm_interface::callback_authentication;
	//callback = &callback_authentication;
	
	protocols[0].name = (const char*) g_malloc0(strlen("authentication_protocol")-1);
	memcpy((void*)protocols[0].name,"authentication_protocol",23);
	//strcpy((char*)protocols[0].name,"authentication_protocol");
	//protocols[0].callback = callback;
	protocols[0].callback = callback_authentication;
	protocols[0].per_session_data_size = 0;
	protocols[0].rx_buffer_size = 4096;

	protocols[1].name = NULL;
	protocols[1].callback = NULL;
	protocols[1].per_session_data_size = 0;
	protocols[1].rx_buffer_size = 0;
	
	wsk_status = WSK_DISCONNECTED;
	init = TRUE;
	g_type_init();
	g_timeout_add( 1000, (GSourceFunc) call_libwebsocket_service,NULL);
	
}

// destructor
comm_interface::~comm_interface(){

	return;
}

struct libwebsocket_context* comm_interface::get_context(){

	return context;
}

time_t comm_interface::get_last_access_time(){
	
	return wsk_last_access_time;
}

time_t comm_interface::get_wsk_time_out(){
	
	return wsk_time_out;
}

time_t comm_interface::get_wsk_keep_alive(){
	
	return wsk_keep_alive;
}

void comm_interface::set_last_access_time(){
	
	wsk_last_access_time = time(NULL);
}

struct libwebsocket* comm_interface::get_wsi(){
	
	return wsi;
}

void comm_interface::wsk_create_context(void){
	
	struct lws_context_creation_info* context_creation_info;
	
	//context_creation_info = g_try_new0(struct_type, n_structs);	//Esto es lo que debo usar en la versión final 
																	//pues la versión de abajo aborta el programa en un error
	context_creation_info = g_new0(struct lws_context_creation_info, 1);

	context_creation_info->port = CONTEXT_PORT_NO_LISTEN;
	context_creation_info->iface = CONF("wsk_iface");
	context_creation_info->protocols = protocols;
	context_creation_info->extensions = libwebsocket_get_internal_extensions();
	context_creation_info->extensions = NULL;
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

	context = libwebsocket_create_context(context_creation_info);
	if (context_creation_info != NULL) g_free(context_creation_info);
}

void comm_interface::wsk_client_connect (void){
	
	// Here there must be selected from the configuration file (sicat.conf), or from the structure nocat_conf, the right value
	// of the variable wsk_server_address based in an specific algorithm. The objetive is to stablish a redundant infrastructure
	// of servers for connect. When that is done the second parameter of libwebsocket_client_connect should change and the whole
	// instruction should be inserted inside a loop that change that parameter until the connection is made. This mecanism should
	// have a timeout.
	
	// ?macAddressFrom=
	
	char* original_url = CONF("wsk_path_on_server");
	char* wsk_url = (char*)calloc(1,strlen(original_url)+16+18);
	strcpy(wsk_url,original_url);
	
	strcat(wsk_url,"?macAddressFrom=");
	strcat(wsk_url,macAddressFrom);
	
	//g_message(wsk_url);	
			
	wsi = libwebsocket_client_connect(context, wsk_server_IP, CONFd("wsk_server_port"),
			CONFd("wsk_use_ssl"),wsk_url,CONF("wsk_server_hostname"),CONF("wsk_origin_name"),
			protocols[CONFd("wsk_protocol")].name, CONFd("ietf_version"));
	
	//g_message("initial wsi = %d with size = %d", (unsigned int)wsi,sizeof(*wsi));
	//g_message("retorno de libwebsocket_client_connect");
		
}

int comm_interface::wsk_send_command(char* comando, struct params* parameters_in, struct data* datos_in){
	
	if (comando != NULL){
		sender_queu->add_frame(comando, parameters_in, datos_in);
		g_message("comm_interface::wsk_send_command: puesta en cola la trama: %s",comando);
	}
	
	libwebsocket_callback_on_writable(context, wsi);
	return 0;
}

void comm_interface::wsk_set_status(enum STATUSES status,const char* function){
	
	char* old_char = (char*)calloc(1,30);
	char* wsk_status_char = (char*)calloc(1,30);
	
	parse_status(wsk_status, old_char);
	wsk_status = status;
	
	parse_status(wsk_status, wsk_status_char);
	
	g_debug("comm_interface::%s: wsk status change from %s to %s",function,old_char,wsk_status_char);
	
	g_free(old_char);
	g_free(wsk_status_char);
	
}

enum STATUSES comm_interface::get_status(){

	return wsk_status;

}

void comm_interface::reset(){
	
	libwebsocket_context_destroy (context);
	wsi = NULL;
	context = NULL;
	set_last_access_time();
}

bool comm_interface::is_init(){
	
	return init;
}

void comm_interface::clear_init(){
	
	init = FALSE;
}

void comm_interface::set_init(){
	
	init = TRUE;
}

int comm_interface::solve_dns(GHashTable *conf){
	
	// Inicializar el proceso de resolución de nombre del servidor websocket.
	// Valores que retorna:
	//  0 - la variable wsk_server_IP ya es una dirección IP válida.
	//  1 - se inició el proceso de resolución de IP, hay que esperar.
	// -1 - error en el proceso de inicialización del proceso de resolución DNS.
	
	// Primero debo chequear que la variable del archivo de configuración no sea ya
	// una dirección ip, en cuyo caso no hay que hacer nada.
	
	gchar *addr;

	addr = (gchar*) g_hash_table_lookup(conf,(gchar *)"wsk_server_address");
	
	if (addr != NULL){
		
		if (is_IP(addr)) {
			
			// La variable del archivo de configuración es una dirección IP válida, por lo tanto
			// no hay que resolver DNS.
			
			if (wsk_server_IP == NULL) {		// Si la variable es NULL es porque esta es la primera vez
												// que se chequea, por lo tanto se le asigna el valor que
												// hay en el archivo de configuración y se retorna informando
												// que no hay que resolver DNS. Si la variable no era NULL es
												// porque esta no es la primera vez que se chequea, por lo
				wsk_server_IP = g_strdup(addr);	// tanto en un chequeo anterior ya se había establecido su				
				g_debug(						// valor correcto, se retorna y ya.
				"comm_interface::solve_dns \
				direccion IP del servidor \
				websockets: %s",wsk_server_IP);
			}													
			return 0;
		}
		else {
			
			// la variable no era un ip, por lo tanto hay que resolver DNS.
			
			g_message("comm_interface::solve_dns: solving IP address for wsk server: %s",addr);
			
			resolver->solve_address((unsigned char*)addr,T_A,set_wsk_server_IP,NULL);
			
			return 1;	
		}
	}
	else {
		
		g_message("comm_interface::solve_dns: the sicat.conf \
		variable wsk_server_address could not be NULL, aborting..");
		g_assert(0);
		return -1;
	}
}

/*void comm_interface::set_wsk_server_IP(struct sockaddr_in** addresses){
	
	g_free(wsk_server_IP);
	wsk_server_IP = g_strdup(server_IP);
	g_debug("comm_interface::set_wsk_server_IP: direccion IP del servidor websockets: %s",wsk_server_IP);
}*/

int comm_interface::wsk_initialize(){
	
	int r = -1;
	int x;
	
	r = solve_dns(nocat_conf);
			
	switch (r) {
		
		case	-1:
		
			return -1;
			
		case	0:
			
			x = wsk_create();
	
			if (x == -1){
				
				// Aquí debo avisar a la administración del sistema de que ha habido un probrema en el
				// establecimiento del wsk.

				g_warning("comm_interface::wsk_initialize: websocket initialization error, retrying...");
				
				return -1;
			}
			break;
			
		case	1:
		
			wsk_set_status(WSK_WAITING_DNS,"wsk_initialize");
			
		default:
			break;
	}
	return 0;
}

int comm_interface::wsk_create(){

	if (context == NULL){
		
		g_message("comm_interface::wsk_create: Creating the libwebsocket context..");
	
		wsk_create_context();

		if (context == NULL) {

			g_warning("comm_interface::wsk_create: Could not create the websocket context, exiting..");
			return -1;
		}
		
		wsk_client_connect();

		if (wsi == NULL) {

			libwebsocket_context_destroy (context);
			g_warning("comm_interface::wsk_create: libwebsocket client connect failed...");
			return -1;
		}
		else {
			
			wsk_set_status(WSK_WAITING_CONFIRM,"wsk_create");
			set_last_access_time();
			
		}
		
		libwebsocket_callback_on_writable(context, wsi);
	}
	return 0;

}

void comm_interface::wsk_restart(){
	
	set_last_access_time();
	if ((wsk_status == WSK_DISCONNECTED) || (wsk_status == WSK_CLOSED)) set_init();

}
#endif
/***************************** end class wsk_comm_interface methods ****************/
