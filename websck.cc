#include "websck.h"

extern class comm_interface* wsk_comm_interface;

int callback_authentication(struct libwebsocket_context* thi, struct libwebsocket* wsi, enum libwebsocket_callback_reasons reason, 
			void *user, void *in, size_t len) {
 
	switch (reason) {
		
		case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
			
			lwsl_err("LWS_CALLBACK_CLIENT_CONNECTION_ERROR");
			
			wsk_comm_interface->wsk_set_status(WSK_ERROR);
			
			break;
			
		case LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH:
		
			lwsl_notice("LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH");
			break;

		case LWS_CALLBACK_CLIENT_ESTABLISHED:

		 	lwsl_notice("LWS_CALLBACK_CLIENT_ESTABLISHED");
			
			wsk_comm_interface->wsk_set_status(WSK_CLIENT_ESTABLISHED);
		 	
			break;
			
		case LWS_CALLBACK_CLOSED:
			 
			lwsl_notice("LWS_CALLBACK_CLOSED");
						
			wsk_comm_interface->wsk_set_status(WSK_CLOSED);
			return -1;
 
			break; 

		case LWS_CALLBACK_CLIENT_RECEIVE:
			
			lwsl_notice("LWS_CLIENT_RECEIVE");
			lwsl_debug("recibidos %d  bytes",len);
			
			wsk_comm_interface->reception_queu->receive_frame((char *)in,len);

			break;

		case LWS_CALLBACK_CLIENT_RECEIVE_PONG:
		
			lwsl_notice("LWS_CALLBACK_CLIENT_RECEIVE_PONG");
					
			break;
			
		case LWS_CALLBACK_CLIENT_WRITEABLE:

			if (wsk_comm_interface->get_status() == WSK_IDDLE){
				 
				 lwsl_notice("Begining wsk close secuence..");
				 return -1;
			}
			
			lwsl_notice("LWS_CLIENT_WRITEABLE");
			
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
		
			lwsl_notice("LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS");
			break;
			
		case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		
			lwsl_notice("LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER");
 			break;
 			
 		/* because we are protocols[0] ...  */

		case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:
		
			lwsl_notice("LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED");
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
		
			lwsl_notice("LWS_CALLBACK_PROTOCOL_INIT");
 			break;

 		case LWS_CALLBACK_ADD_POLL_FD:
 		
 			lwsl_notice("LWS_CALLBACK_ADD_POLL_FD");
 			break;
 			
		case LWS_CALLBACK_DEL_POLL_FD:
		
 			lwsl_notice("LWS_CALLBACK_DEL_POLL_FD");
 			break;
 			
 		case LWS_CALLBACK_SET_MODE_POLL_FD:
 		
 			lwsl_notice("LWS_CALLBACK_SET_MODE_POLL_FD");
 			break;
 			
		case LWS_CALLBACK_CLEAR_MODE_POLL_FD:
		
			lwsl_notice("LWS_CALLBACK_CLEAR_MODE_POLL_FD");
			break;
			
		case LWS_CALLBACK_PROTOCOL_DESTROY:
		
			lwsl_notice("LWS_CALLBACK_PROTOCOL_DESTROY");
			wsk_comm_interface->wsk_set_status(WSK_DISCONNECTED);
			break;
				
		default:
		
			lwsl_err("Libwebsocket callback function called with unnatended reason (%d)",(int)reason);

			break; 
	}
	
	return 0;
}

gboolean call_libwebsocket_service(void* dummy){
	
	switch (wsk_comm_interface->get_status()){
		
		case WSK_WAITING_CONFIRM:
		
			// Aquí debiera incluir un contador para un timeout.
			//return TRUE;
			break;
			
		case WSK_ERROR:
		
			wsk_comm_interface->reset();
			break;
			
		case WSK_CLOSED:
			
			wsk_comm_interface->reset();
			break;
			
		case WSK_CLIENT_ESTABLISHED:
		
			if (difftime(time(NULL),wsk_comm_interface->get_last_access_time())
				 > wsk_comm_interface->get_wsk_time_out()){
				 	
				 wsk_comm_interface->wsk_set_status(WSK_IDDLE);
				 libwebsocket_callback_on_writable(wsk_comm_interface->get_context(),
				 									wsk_comm_interface->get_wsi());
			}
			break;
			
		case WSK_DISCONNECTED:
		
			if (!(wsk_comm_interface->is_init())){
				
				if (difftime(time(NULL),wsk_comm_interface->get_last_access_time())
				 > wsk_comm_interface->get_wsk_keep_alive()) {
					
					wsk_comm_interface->wsk_send_command(NULL, NULL, NULL);
				 	
				}
				else return TRUE;
			}
			else{
				
				wsk_comm_interface->clear_init();
				wsk_comm_interface->wsk_send_command(NULL, NULL, NULL);
			}
			
			break;
			
		default:
			break;
		
	}
	
	libwebsocket_service(wsk_comm_interface->get_context(),0);

	return TRUE;
		
}

/***************************** class m_frame methods *******************************/
#ifdef MFRAME

// class m_frame constructor from a message (parse an arrived message to a class m_frame)
m_frame::m_frame(char* message, unsigned int m_size, bool* correct){

	int left;
	char* str_temp = NULL, * str_temp1 = NULL, * str_temp2 = NULL;

	command_name = NULL;
	parameters = NULL;
	datos = NULL;
	readed = false;
	m_frame_as_message = NULL;
	memset (frame_type,0,2);

	char* buffer_end = message + m_size -1;

	if (m_size >= 20){	//Si el tamaño del mensaje es mayor que el tamaño mínimo del encabezamiento + la secuencia terminal.

		// Basta con que uno de los delimitadores de campos no esté en su lugar para que se descarte
		// el buffer message como una trama.
		//g_message("el comando tiene el tamaño mínimo");
		if ( (memcmp ("_###_", message, 5) != 0) || (memcmp ("_", message + 7, 1) != 0) ||
			(memcmp ("_", message + 10, 1) != 0 ) || (memcmp ("_", message + 13, 1) != 0 ) ||
			(memcmp ("_", message + 15, 1) != 0 ) ) return;
		//g_message("encabezamiento y delimitadores ok");
		// Adquirir los campos del encabezamiento

		m_frame_index = (unsigned short int)*((char*)message + 5);
		m_frame_index_ack = (unsigned short int)*((char*)message + 8);
		body_size = (unsigned short int)*((char*)message + 11);
		memcpy(frame_type,(char*)message+14,1);//(char)*((char*)message + 14);
		//g_message("frame_type = %s",frame_type);
		// si el campo body_size == 0 y el tipo de trama no es acknowledge entonces es un error, retornar.
		//if ((body_size == 0) && (strcmp("A",frame_type) != 0))	return;
		if ((body_size == 0) && (memcmp("A",frame_type,1) != 0))	return;

		// Ya se extrajo el encabezamiento, ahora se pasa al cuerpo, empezando por quitar el terminador final.
		//g_message("procesando el cuerpo del mensaje");
		message = message + 15;
		m_size = m_size - 15;

		if (memcmp ("_###_", buffer_end - 4, 5) != 0) return;
		
		buffer_end = buffer_end - 4;
		*(buffer_end) = 0;

		// Ya se extrajo el terminador final, ahora vamos a dividir el área de comandos del área de datos.

		left = buffer_end - message;
		if (left == 0){	// No hay nada entre el final y el principio del área de comandos.

			if (memcmp("A",frame_type,1) == 0){
				*correct = true; // Si la trama es ack no hay lío, es correcto.
				//print();
			}
			return;

		}
		// Buscar el delimitador entre el área de comandos y el área opcional de datos.
		str_temp = (char*) (memchr (message,':',left)); //parameters

		if (str_temp != NULL){	// Esto significa que se encontró un caracter : que debe delimitar un
								// área de datos.

			int data_size = (int)((unsigned int) buffer_end - (unsigned int) str_temp);

			if (data_size > 0) {	// Hay datos en la zona de datos.

				datos = g_new0(struct data, 1);
				datos->size = data_size;
				datos->binaries = (char*)g_malloc0(data_size);
				g_memmove(datos->binaries,(str_temp + 1),data_size);

			}
			*str_temp = 0;
			buffer_end = str_temp;

			left = buffer_end - message;

			if (left == 0) return;	// Había área de datos pero no de comandos, error.

		}
		// Ya aquí extraje los datos, de haberlos, ahora a extraer el nombre del comando y los parámetros.

		str_temp = strtok ((char*)(message+1), "_");

		if (str_temp != NULL){

			command_name = (char*)g_malloc0(strlen(str_temp)+2);
			strcpy(command_name,str_temp);

			bool first_entrance = true;

			while ( (str_temp = (strtok (NULL, "_"))) != NULL){

				if (first_entrance){

					parameters = g_new0(struct params,1);
					first_entrance = false;

				}
				str_temp1 = (char*)g_malloc0(strlen(str_temp)+2);
				strcpy(str_temp1,str_temp);

				parameters->cantidad++;
				if (parameters->cantidad > 1){

					str_temp2 = (char*)parameters->values;

				}
				parameters->values = (char**)g_malloc0(parameters->cantidad);
				if (parameters->cantidad > 1){

					for (unsigned int i = 0;i<parameters->cantidad-1;i++){
						parameters->values[i] = ((char**)str_temp2)[i];
					}
					g_free((char**)str_temp2);
				}
				parameters->values[parameters->cantidad-1] = str_temp1;
			}
		}
		else {
			
			*correct = false;
			return;
		}
		
		*correct = true;
		return;
	}
	else *correct = false;
}

// class m_frame constructor from fields (build a class m_frame given certain fields)
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
}

// class m_frame destructor
m_frame::~m_frame(){

	//g_message("entré al destructor de m_frames");
	//g_message("nombre del comando a destruir: %s",command_name);
	
	g_free(command_name);
	
	if (m_frame_as_message != NULL) g_free(m_frame_as_message);
	
	if (parameters != NULL){
		for (unsigned int i=0; i<parameters->cantidad;i++){

			if (parameters->values[i] != NULL) g_free(parameters->values[i]);
		}
	}
	g_free(parameters);

	if (datos != NULL){
		if (datos->binaries != NULL) g_free(datos->binaries);
		g_free(datos);
	}
}

unsigned short int m_frame::get_index(){

	return m_frame_index;
}

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
	
	/*bool corr;
	m_frame* tempo = new class m_frame((char*)buffer,20,&corr);
	delete tempo;*/
	
	
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
}
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
	
		lwsl_err("ups: trama incorrecta..");
		
		char* tem = (char*)g_malloc0(message_size + 2);
		memcpy(tem,message,message_size);
		lwsl_err(tem);
		g_free(tem);
		delete temp_frame;
		return false;
	}
	
	// Aquí chequeo si es una trama ack, en caso de serlo por el momento solamente se descarta esta y ya.
	// En un futuro se deberá chequear en la cola de salida la trama que está esperando por el ack, se elimina de la
	// cola de salida (tomando las medidas extras necesarias como resetear contadores de espera para reenvío, etc) y 
	// se elimina la trama ack recientemente llegada.
	
	if (memcmp(temp_frame->get_frame_type(),"A",1) == 0){
		lwsl_notice("recibido un ack");
		delete temp_frame;
		wsk_comm_interface->set_last_access_time();
		return true;
	}
	
	// Chequear que no haya otra trama en la cola que tenga el mismo index, de ser así eliminar la trama
	// llegada y retornar false.

	for (int i = 0;i<count;i++){

		if (ptr_frames[i]->get_index() == temp_frame->get_index()){

			lwsl_err("repeated frame arrived :%s, descarted...",temp_frame->print());
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
	lwsl_debug("recibida la trama: %s",ptr_frames[count]->print());
	count++;
	wsk_comm_interface->set_last_access_time();
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

	bool right = false;

	// Crear una clase m_frame con la información que se quiere transmitir.

	class m_frame* temp_frame = new m_frame(comando,parameters_in,datos_in, &right);

	if (!right){	// Si hubo algún problema en la creación de la clase m_frame eliminarla y retornar false.
		delete temp_frame;
		return false;
	}

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
	ptr_frames[count] = temp_frame;
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
			
				if (memcmp(ptr_frames[0]->get_frame_type(),"A",1) == 0) message_size = 20;
				else message_size = 21 + (ptr_frames[0]->get_body_size());
				
				unsigned char buffer[LWS_SEND_BUFFER_PRE_PADDING + message_size + LWS_SEND_BUFFER_POST_PADDING];
				
				// _###_00_00_00_C_LISTPARAMS_15_abcd_efgh:1234567890_###_
				// _###_00_00_00_C_INIT_###_      25 caracteres
				//g_message ("creando el mensaje desde la m_frame");
				memcpy(&(buffer[LWS_SEND_BUFFER_PRE_PADDING]),ptr_frames[0]->as_message(),message_size);
				
				//g_message ("voy a enviar");
				int result = libwebsocket_write(wsi,
							&buffer[LWS_SEND_BUFFER_PRE_PADDING], message_size, LWS_WRITE_BINARY);

				//g_message("enviados = %d",result);
				//g_message("%d",ptr_frames[0]->get_body_size());

				if (result == (int)message_size){

					//tempo = ptr_frames[0]->get_index();
					lwsl_debug("enviada la trama: %s",ptr_frames[0]->print());
					delete_frame(ptr_frames[0]->get_index());
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
		}
	}
	return false;
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
	
	wsk_status = WSK_DISCONNECTED;
	
	wsi = NULL;
	
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
	
	init = TRUE;
	wsk_status = WSK_DISCONNECTED;
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
	
	// Here there must be selected from the configuration file (nocat.conf), or from the structure nocat_conf, the right value
	// of the variable wsk_server_address based in an specific algorithm. The objetive is to stablish a redundant infrastructure
	// of servers for connect. When that is done the second parameter of libwebsocket_client_connect should change and the whole
	// instruction should be inserted inside a loop that change that parameter until the connection is made. This mecanism should
	// have a timeout.
	
	//wsi_dumb = libwebsocket_client_connect(context, wsk_server_address, wsk_server_port, CONFd("wsk_use_ssl"), CONF("wsk_path_on_server"),
	//			CONF("wsk_server_hostname"), CONF("wsk_origin_name"), protocols[CONFd("wsk_protocol")].name, CONFd("ietf_version"));
				
	/*wsi = libwebsocket_client_connect(context, CONF("wsk_server_address"), CONFd("wsk_server_port"),
				 CONFd("wsk_use_ssl"), CONF("wsk_path_on_server"),
				 "datalnet.azurewebsites.net","http://localhost:65487", protocols[CONFd("wsk_protocol")].name, CONFd("ietf_version"));*/
				 
	wsi = libwebsocket_client_connect(context, CONF("wsk_server_address"), CONFd("wsk_server_port"),
				 CONFd("wsk_use_ssl"), CONF("wsk_path_on_server"),
				 CONF("wsk_server_hostname"),CONF("wsk_origin_name"), protocols[CONFd("wsk_protocol")].name, CONFd("ietf_version"));
	
	//g_message("initial wsi = %d with size = %d", (unsigned int)wsi,sizeof(*wsi));
		
}

int comm_interface::wsk_send_command(char* comando, struct params* parameters_in, struct data* datos_in){
	
	if (context == NULL){
	
		lwsl_notice("Creating the libwebsocket context..");
	
		wsk_create_context();

		if (context == NULL) {

			lwsl_err("Could not create the websocket context, exiting..");
			return -1;
		}
		
		wsk_client_connect ();

		if (wsi == NULL) {

			lwsl_err("libwebsocket client connect failed...");
			return -1;
		}
		else {
			
			wsk_status = WSK_WAITING_CONFIRM;
			set_last_access_time();
			
		}
	
		char* coma;
		parametros* par;
		data* da;
		
		coma = (char*)g_malloc0(5);
		strcpy(coma,"INIT");
		
		par = NULL;
		da = NULL;
		
		/*parametros* par = g_new0(struct params, 1);
		par->cantidad = 2;
		par->values = (char**)g_malloc0(par->cantidad);
		
		char* para = (char*)g_malloc0(3);
		strcpy(para,"12");
		
		par->values[0] = para;
		
		char* para1 = (char*)g_malloc0(18);
		strcpy(para1,"12345678901234567");
		
		par->values[1] = para1;
		
		data* da = g_new0(struct data, 1);
		da->size = 10;
		
		char* d = (char*)g_malloc0(11);
		g_memmove(d,"0123456789",10);
		
		da->binaries = d;*/
		
		sender_queu->add_frame(coma, par, da);
		g_message("adicionada la trama init: %s",coma);
			
	}
	
	if (comando != NULL){
		sender_queu->add_frame(comando, parameters_in, datos_in);
		g_message("adicionada la trama: %s",comando);
	}
	
	libwebsocket_callback_on_writable(context, wsi);
	return 0;
}

void comm_interface::wsk_set_status(enum STATUSES status){
	
	wsk_status = status;
	
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


#endif
/***************************** end class wsk_comm_interface methods ****************/
