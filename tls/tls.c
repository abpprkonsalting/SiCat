# include "tls.h"

extern GHashTable* ssl_certificates_tab;
extern GHashTable* ssl_connected_tab;
extern jmp_buf state;
//extern jmp_buf previous_state;
extern int test_var;

SSL_METHOD *global_extern_ssl_method;
SSL_CTX *global_extern_ctx;

#define SERVER_NAME_LEN 256
#define TLS_HEADER_LEN 5
#define TLS_HANDSHAKE_CONTENT_TYPE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01

static const char tls_alert[] = {
    0x15, /* TLS Alert */
    0x03, 0x01, /* TLS version  */
    0x00, 0x02, /* Payload length */
    0x02, 0x28, /* Fatal, handshake failure */
};

gchar* get_certificate(ssl_connection* s){
	
	gchar* tempo;
	
	if (s->server_certificate != NULL) return s->server_certificate;
	else {
		// Aqu'i primero se busca en la cache de certificados en base al SNI a ver si ya tenemos un certificado
		// para ese servidor, sino se comienza el proceso de sniffeado del certificado desde el servidor real.
	
		if ( strcmp(s->SNI,"\0") != 0){	//Esto significa que el SNI tiene un nombre verdadero.
		
			tempo = (gchar*) g_hash_table_lookup(ssl_certificates_tab, s->SNI);
			
			if ( tempo != NULL) {
				
				s->server_certificate = tempo;
				return tempo;
			}
		}
		// Si se llega hasta aqu'i es porque originalmente no habia un SNI, o porque en la cache de certificados no
		// hab'ia un certificado que representara al servidor. En cualquiera de los dos casos se deber'a iniciar
		// el proceso de sniffeado, para lo cual retornamos NULL y en la funci'on que llam'o a esta se comienza el 
		// sniffeado.
		return NULL;
	}
}

int checkSNI(ssl_connection* s){
	
	gchar* certificate;
	int m;
	
	if (s->capture_status == 0) {
		s->arreglo_source_ids[3] = g_timeout_add_full(G_PRIORITY_DEFAULT,30000,(GSourceFunc)time_out_SNI,s,(GDestroyNotify)destroy_ssl_conn);
		s->ref_count++;
		g_debug("checkSNI: s = %u, ref_count = %u, adding time_out_SNI",s->secuence_number,s->ref_count);
		s->capture_status = 1;
	}
	s->SNI = parse_tls_header(s->ssl_queue->first->buffer,s->ssl_queue->first->tamanno);
	
	if (s->SNI != NULL) {
		
		// Se recibi'o el client hello correctamente, tenga o no un SNI.
		
		g_debug("checkSNI: s = %u: se recibio el SNI = %s",s->secuence_number, s->SNI);
		
		// Lo primero que se hace es buscar en la cache local de certificados a ver si hay alguno que corresponda
		// al servidor que queremos suplantar.
		certificate = get_certificate(s);
		
		if (certificate != NULL){	// Voala, no hay necesidad de esperar porque ya est'a el certificado en la cache
									// interna.
		//if (1){
			
			if (s->Channels_array[1]  == NULL) {
				
				s->capture_status = 6;
				m = connect_to_internal_openssl(s);
				if (m == -1) {
					
					g_debug("checkSNI: s = %u: no se pudo establecer conexi'on con openssl, abortando la conexión del cliente"\
								,s->secuence_number);
					
					return -1;
				}
			}
		}
		else {
			//Iniciar el proceso de sniffeado.
			m = connect_to_real_server(s);
			
			if (m < 0){
				
				// Ocurrio un error durante la conexi'on al servidor real, lo que no quiere decir que no se pueda
				// hacer el proceso de portal cautivo. Si en el client hello originalmente hab'ia un SNI entonces
				// creamos un certificado falso a partir de ese SNI y datos de Datalnet, y lo usamos para hacer el
				// MITM.
				// Si no hab'ia un SNI en el client hello original entonces hay que resolver por DNS el nombre (o los
				// nombres ? ) que est'an registrados para la direcci'on IP de destino original de la conexi'on SSL
				// del cliente y hacer el certificado para ese (esos) nombres de dominio.
				// Si no se puede resolver DNS entonces si que no queda m'as remedio que tratar esto como un error.	
			}
		}
	}
	return 0;	
}

gboolean time_out_SNI(ssl_connection* s) {
	
	if (s->capture_status < 2) {
	
		// Pasaron 30 segundos y no se ha recibido el client hello correctamente
		// por lo tanto de una manera o de otra esta conexi'on es un error.
		
		// This is a fatal error, so we have to mark the ssl_connection for destroy in the GDestroyNotify function
		s->mark_destroy = TRUE;
		// Also we must mark every channel to be destroyed
		s->Channels_array[0] = NULL;
		s->Channels_array[1] = NULL;
		s->Channels_array[2] = NULL;
		
	}
	
	//s->arreglo_source_ids[3] = 0;
	s->ref_count--;
	g_debug("time_out_SNI: s = %u, ref_count = %u, exitting",s->secuence_number,s->ref_count);
	return FALSE;
}

gboolean timer_output_client_channel(ssl_connection* s) {
	
	if (s->Channels_array[0] != NULL) {		// This implies that the channel is, at least, marked to be destroyed, so there is not need to
											// continuing writting the queue to the client.
	
		if (s->capture_status == 7) {
			
			///g_debug("timer_output_client_channel: s = %u: entering",s->secuence_number);
			
			struct ssl_buffer* buffer_a_enviar = NULL;
			if (s->ssl_queue_r->just_sended == NULL) {
				
				if (s->ssl_queue_r->first != NULL) {
					
					buffer_a_enviar = s->ssl_queue_r->first;
					g_debug("timer_output_client_channel: s = %u: sending to the client the first buffer of the queue",s->secuence_number);
				}
				else return TRUE;
			}
			else if (s->ssl_queue_r->just_sended->next == NULL) return TRUE;
			else buffer_a_enviar = s->ssl_queue_r->just_sended->next;
			
			int ret = write(g_io_channel_unix_get_fd(s->Channels_array[1]),buffer_a_enviar->buffer,buffer_a_enviar->tamanno);
			
			if (ret == (ssize_t)(buffer_a_enviar->tamanno)){
					
				// Se escribió todo el buffer (lo que deberá ocurrir la mayoría de las veces).
				
				g_message("timer_output_client_channel: s = %u: enviado un buffer al cliente",s->secuence_number);
				
				s->ssl_queue_r->just_sended = buffer_a_enviar;
				
				if ( s->ssl_queue_r->just_sended->previous != NULL) {
					
					g_free(s->ssl_queue_r->just_sended->previous->buffer);
					g_free(s->ssl_queue_r->just_sended->previous);
					s->ssl_queue_r->just_sended->previous = NULL;
					
				}
			}
			else if (ret == -1){
			
				switch (errno){
					
				case EAGAIN:
				
					// It's really necessary to repeat the operation in this case? It's yet to be tested.
					
					g_message("timer_output_client_channel: s = %u: write returned with EAGAIN",\
									s->secuence_number);
					
					/*s->ssl_queue_r->just_sended = buffer_a_enviar;
				
					if ( s->ssl_queue_r->just_sended->previous != NULL) {
						
						g_free(s->ssl_queue_r->just_sended->previous->buffer);
						g_free(s->ssl_queue_r->just_sended->previous);
						s->ssl_queue_r->just_sended->previous = NULL;
						
					}*/
					break;
					
				case EINTR:
					
					// This means that the write operation was interrupted by a signal sended to the program, so it's necessary to repeat the
					// operation. The use of the macro TEMP_FAILURE_RETRY is not convenient here because if the condition that generated the
					// signal is not solved (somehow ?) this could lead to an infinite cycle that blocks the program. Any way, as this function
					// is a callback for the GIOChannel that is called when the Channel can accept output operations it is enough to return TRUE
					// here in order to repeat the write operation later.
					
					g_message("timer_output_client_channel: s = %u: write returned with EINTR",\
									s->secuence_number);
				
					break;
	
				default:
				
					// Otro tipo de error, hay que cancelar la conexión del cliente.
					
					g_message("timer_output_client_channel: s = %u: error en la escritura de un buffer al cliente",\
									s->secuence_number);
					
					buffer_a_enviar->write_tries++;
					
					if (buffer_a_enviar->write_tries > 10) {
						
						g_message("timer_output_client_channel: s = %u: timeout en la escritura de un buffer al cliente, aborting..",\
									s->secuence_number);
									
						s->Channels_array[0] = NULL;
						s->Channels_array[1] = NULL;
						s->Channels_array[2] = NULL;
						
						//g_io_channel_shutdown(s->Channels_array[0],FALSE,NULL);
						//g_io_channel_unref(s->Channels_array[0]);
						
						s->ref_count--;
						g_debug("timer_output_client_channel: s = %u, ref_count = %u, exitting",s->secuence_number,s->ref_count);
						//s->arreglo_source_ids[0] = 0;
						//s->arreglo_source_ids[5] = 0;
						
						// This is a fatal error, so we have to mark the ssl_connection for destroy in the GDestroyNotify function
						
						s->mark_destroy = TRUE;
					
						return FALSE;
					}
					break;
				}
			}
			else if ((ret > 0) && (ret < (ssize_t)(buffer_a_enviar->tamanno))){
						
				g_message("timer_output_client_channel: s = %u: no se terminó de escribir un buffer al cliente",\
									s->secuence_number);
			
				buffer_a_enviar->buffer = buffer_a_enviar->buffer + ret;
				buffer_a_enviar->tamanno = buffer_a_enviar->tamanno - ret;
			}
		}
		/*else {
			
			I need to contemplate the posibility that before status == 7 I could send something saying to the client that it must wait.
		}
		*/
	}
	else {
		
		s->ref_count--;
		g_debug("timer_output_client_channel: s = %u, ref_count = %u, exitting",s->secuence_number,s->ref_count);
		return FALSE;
	}
}

/*void agregar_source_id(ssl_connection* s, guint source_id) {
	
	(s->arreglo_source_ids[0])++;
	guint* new_array = g_new0(guint,s->arreglo_source_ids[0] + 1);
	memcpy(new_array,s->arreglo_source_ids,s->arreglo_source_ids[0]);
	g_free(s->arreglo_source_ids);
	s->arreglo_source_ids = new_array;
	s->arreglo_source_ids[s->arreglo_source_ids[0]] = source_id;
	return;
}

void eliminar_source_id(ssl_connection* s, guint source_id) {
	
	// This function does not remove the source_id, it just mark it as removed by means of writting 0 to it.
	
	guint* ref = s->arreglo_source_ids + (guint*)1;
	
	do {
			if (*ref == source_id) break;
			ref++;
			
	} while (ref <= (s->arreglo_source_ids + (guint*)(s->arreglo_source_ids[0])));
	
	if (*ref == source_id) {
		
		*ref = 0;
	}
	return;
}*/

ssl_connection* ssl_connection_new(GIOChannel* channel,guint secuence_number) {

    ssl_connection* s = g_new0(ssl_connection, 1);	// s[0xXXX] = 0x001 (ssl_structure) // s[0xXXX] is a local variable, destroyed upon return 
													// from this function, it's value is 0x001 the address where is located the ssl_structure.
    
    struct sockaddr_in addr;
    int n = sizeof(struct sockaddr_in);
    int r;
    const gchar* r2;

    s->secuence_number = secuence_number;
    s->mark_destroy = FALSE;
    s->ref_count = 0;
    
    s->Channels_array = g_new0(GIOChannel*,3);
    s->Channels_array[0] = channel;
	
	s->arreglo_source_ids = g_new0(guint,7);
	
	s->ssl_queue = g_new0(struct queue,1);
	
	s->ssl_queue->first = NULL;
	s->ssl_queue->last = NULL;
	s->ssl_queue->just_sended = NULL;
	
	s->ssl_queue_r = g_new0(struct queue,1);
	
	s->ssl_queue_r->first = NULL;
	s->ssl_queue_r->last = NULL;
	s->ssl_queue_r->just_sended = NULL;
	
	s->capture_status = 0;	// Se acaba de crear la conexi'on, no se ha empezado el proceso de sniffeado de certificado.
	s->SNI = NULL;
	s->server_certificate = NULL;
	
    r = getsockname(g_io_channel_unix_get_fd(channel), (struct sockaddr *)&addr, (socklen_t*)&n );
    if (r == -1) { 
    	g_message( "ssl_connection_new: getsockname failed: %m" );
    	destroy_ssl_conn(s);
    	return NULL;
    }
    r2 = inet_ntop( AF_INET, &addr.sin_addr, s->sock_ip, INET_ADDRSTRLEN );

    r = getpeername(g_io_channel_unix_get_fd(channel), (struct sockaddr *)&addr, (socklen_t*)&n );
    if (r == -1){
    	g_message( "ssl_connection_new: getpeername failed: %m" );
    	destroy_ssl_conn(s);
    	return NULL;
    }
    r2 = inet_ntop( AF_INET, &addr.sin_addr, s->peer_ip, INET_ADDRSTRLEN );
    
    s->peer_port = ntohs(addr.sin_port);
    
	s->hw = arp_get(s->peer_ip);
	
	s->key = g_new0(char,40);
		
	strcat(s->key,s->hw);
	strcat(s->key,"//");
	strcat(s->key,s->peer_ip);
		
	gchar* puerto_origen = g_new0(gchar,4);
	sprintf (puerto_origen, "%d",s->peer_port);
		
	strcat(s->key,":");		
	strcat(s->key,puerto_origen);
	
	g_free(puerto_origen);
	
	s->remote_ip = (gchar*) g_hash_table_lookup(ssl_connected_tab,s->key);
	
	//g_debug("http_request_new: real remote ssl server = %s",h->ssl_remote_ip);
	
	s->real_server_certificate = NULL;
	
	s->connect_atemp = 0;
	
    return s;	// return 0x001, the value of the s variable.
}

void destroy_ssl_conn(ssl_connection* s) {		//ss[0x002] = (0x001)		s[0x001] = (0x00a)      [0x00a] = (ssl_structure ... )
	
	/*if (**ss != NULL){ // *(0x001) = 0x00a
		
		if ( (*ss)->mark_destroy == TRUE) {
			
			GSource* source;
				
			if ((*ss)->real_server_ssl != NULL)  SSL_free((*ss)->real_server_ssl);	// Esto va primero porque su funcionamiento debe depender 
																					// del canal externo por lo que este debe estar vivo.
			
			for (guint i = 0; i < 5; i++){
				
				if ((*ss)->arreglo_source_ids[i] != 0) {
					
					source = g_main_context_find_source_by_id(NULL,(*ss)->arreglo_source_ids[i]);
					g_source_destroy(source);
					g_source_unref(source);
				}
			}
			for (guint i = 0; i < 3; i++){
				
				if ((*ss)->Channels_array[i] != NULL) {
					g_io_channel_shutdown((*ss)->Channels_array[i],FALSE,NULL);
					g_io_channel_unref((*ss)->Channels_array[i]);
				}
			}
			gboolean removed = g_hash_table_remove(ssl_connected_tab,(*ss)->key);
			if (removed == TRUE) g_debug("destroy_ssl_conn: s = %u: eliminados correctamente la key y el value de la ghashtable",(*ss)->secuence_number);
			g_free((*ss)->key);
			
			g_free((*ss)->hw);
			g_free((*ss)->SNI);
			
			// server_certificate es un puntero a un string que está en algún lado en memoria y que está relacionado con la ghashtable 
			// ssl_certificate_tab, esta tabla se usa para referenciar la cache de certificados almacenados en memoria, por lo tanto cuando 
			// la ssl_connection se destruye no hay que eliminar esta variable, pues el certificado puede seguir en memoria.
			// La eliminación de este valor dependerá del algoritmo de inclusión - eliminación de certificados en la cache.
			
			g_free((*ss)->real_server_certificate);
			
			delete_queue((*ss)->ssl_queue);
			delete_queue((*ss)->ssl_queue_r);
			
																		// s[0x001] = 0x00a(ssl_structure)		ss[0x002] = 0x001
			g_free(*(*ss)));	// g_free(*(0x001)) = g_free(0x00a)		// s[0x001] = 0x00a						ss[0x002] = 0x001
			**ss = NULL;		// *(0x001) => s[0x001] = NULL			// s[0x001] = NULL;						ss[0x002] = 0x001
			//g_free(ss);		// g_free(0x002) =>						// s[0x001] = NULL;		
		}
	}
	g_free(ss);*/
	
	/*jmp_buf previous_state = state;		// Salvar el estado anterior a esta prueba.
	test_var = setjmp(state);			// prepare for the crash.
	//g_debug("destroy_ssl_conn: s = %u: entering",s->secuence_number);
	
	switch (test_var){
		
		case 0:		// This is the normal return of the setjmp function when we first enter the destroy_ssl_conn function for the first time
					// and we don't know if the variable s still exist.
					
			//s->mark_destroy = !(s->mark_destroy);	// test the variable s for existence.
			
			// If program execution follows this path it means that the variable s still exist, so we can continue processing it.
			
			if (s->mark_destroy == TRUE){
		
				GSource* source;
				
				if (s->real_server_ssl != NULL)  SSL_free(s->real_server_ssl);	// Esto va primero porque su funcionamiento debe depender 
																				// del canal externo por lo que este debe estar vivo.
				
				for (guint i = 0; i < 5; i++){
					
					if (s->arreglo_source_ids[i] != 0) {
						
						source = g_main_context_find_source_by_id(NULL,s->arreglo_source_ids[i]);
						g_source_destroy(source);
						g_source_unref(source);
					}
				}
				for (guint i = 0; i < 3; i++){
					
					if (s->Channels_array[i] != NULL) {
						g_io_channel_shutdown(s->Channels_array[i],FALSE,NULL);
						g_io_channel_unref(s->Channels_array[i]);
					}
				}
				gboolean removed = g_hash_table_remove(ssl_connected_tab,s->key);
				if (removed == TRUE) g_debug("destroy_ssl_conn: s = %u: eliminados correctamente la key y el value de la ghashtable",s->secuence_number);
				g_free(s->key);
				
				g_free(s->hw);
				g_free(s->SNI);
				
				// server_certificate es un puntero a un string que está en algún lado en memoria y que está relacionado con la ghashtable 
				// ssl_certificate_tab, esta tabla se usa para referenciar la cache de certificados almacenados en memoria, por lo tanto cuando 
				// la ssl_connection se destruye no hay que eliminar esta variable, pues el certificado puede seguir en memoria.
				// La eliminación de este valor dependerá del algoritmo de inclusión - eliminación de certificados en la cache.
				
				g_free(s->real_server_certificate);
				
				delete_queue(s->ssl_queue);
				delete_queue(s->ssl_queue_r);
				g_free(s);	
			}
			//else s->mark_destroy = !(s->mark_destroy);	// restoring the variable to it's original value.
			break;

		case 1:						// This is the return from the handler of the signal SIGSEGV.
		
			g_debug("destroy_ssl_conn: recovering from a segmentation violation (SIGSEGV) destroying an already destroyed ssl_connection struct");	
			break;
		case 2:
			g_debug("destroy_ssl_conn: recovering from a bus error (SIGBUS) destroying an already destroyed ssl_connection struct");
			break;
		default:
			g_debug("destroy_ssl_conn: I don't know what this is happening");
			break;
	}
	g_debug("destroy_ssl_conn: s = %u: leaving",s->secuence_number);
	state = previous_state;
	*/
	
	if ((s->ref_count == 0) && (s->mark_destroy == TRUE)){
		
		// This is the last source of events destroying itself, so we can free the ssl_connection.
		
		if (s->real_server_ssl != NULL)  SSL_free(s->real_server_ssl);	// Esto va primero porque su funcionamiento debe depender 
																		// del canal externo por lo que este debe estar vivo.
		
		gboolean removed = g_hash_table_remove(ssl_connected_tab,s->key);
		if (removed == TRUE) g_debug("destroy_ssl_conn: s = %u: eliminados correctamente la key y el value de la ghashtable",s->secuence_number);
		g_free(s->key);
		
		g_free(s->hw);
		g_free(s->SNI);
		
		// server_certificate es un puntero a un string que está en algún lado en memoria y que está relacionado con la ghashtable 
		// ssl_certificate_tab, esta tabla se usa para referenciar la cache de certificados almacenados en memoria, por lo tanto cuando 
		// la ssl_connection se destruye no hay que eliminar esta variable, pues el certificado puede seguir en memoria.
		// La eliminación de este valor dependerá del algoritmo de inclusión - eliminación de certificados en la cache.
		
		g_free(s->real_server_certificate);
		
		delete_queue(s->ssl_queue);
		delete_queue(s->ssl_queue_r);
		g_free(s);
	}
	return;
}

char* arp_get(gchar* ip_add) {
	
    char* ip = g_new0(char,50);
    char* hw = g_new0(char,18);
    FILE *arp;

    arp = fopen( "/proc/net/arp", "r" );
    if ( arp == NULL ){
    	g_message( "Can't open /proc/net/arp: %m" );
    	g_free(ip);
    	g_free(hw);
    	return NULL;
    }
   
    fscanf(arp, "%*s %*s %*s %*s %*s %*s %*s %*s %*s"); // Skip first line 
    while (fscanf( arp, "%15s %*s %*s %17s %*s %*s\n", ip, hw ) != EOF){
		if (strcmp( ip_add, ip) == 0 ) 
			{
				//g_strncpy(hw_add, hw, sizeof(hw) );
				g_free(ip);
				fclose(arp);
				return hw;
			}
    }
	g_free(ip);
	g_free(hw);
    fclose(arp);
	return NULL;
}

char *parse_tls_header(const char* data, int data_len) {

/* Parse a TLS packet for the Server Name Indication extension in the client hello
 * handshake, returning the first servername found (pointer to static array) */
	
/* Esta función devuelve los siguientes valores:
 * NULL = a'un no se ha encontrado el SNI
 * \0  = se recibi'o el clienthello pero este no conten'ia un SNI
 * Un string con el SNI recibido*/
 
    char tls_content_type;
    char tls_version_major;
    char tls_version_minor;
    int tls_length;
    const char* p = data;
    int len;
    
    char* no_server_name = g_new0(char,1);

    /* Check that our TCP payload is at least large enough for a TLS header */
    if (data_len < TLS_HEADER_LEN){
		
		g_debug("parse_tls_header: los datos recibidos no llegan ni a un TLS_HEADER_LEN");
		g_free(no_server_name);
        return NULL;
	}

    tls_content_type = p[0];
    if (tls_content_type != TLS_HANDSHAKE_CONTENT_TYPE) {
        g_debug("parse_tls_header: Lo que se ha recibido no es un TLS handshake");
        g_free(no_server_name);
        return NULL;
    }

    tls_version_major = p[1];
    tls_version_minor = p[2];
    if (tls_version_major < 3) {
        g_debug("parse_tls_header: Se recibi'o un handshake con formato previo a SSL 3.0");
        g_free(no_server_name);
        return NULL;
    }

    if (tls_version_major == 3 && tls_version_minor < 1) {
        g_debug("parse_tls_header: Se recibi'o un handshake con formato SSL 3.0");
        g_free(no_server_name);
        return NULL;
    }

    tls_length = ((unsigned char)p[3] << 8) + (unsigned char)p[4];
    if (data_len < tls_length + TLS_HEADER_LEN) {
        g_debug("parse_tls_header: No se ha recibido un handshake completo");
        g_free(no_server_name);
        return NULL;
    }



    /* Advance to first TLS payload */
    p += TLS_HEADER_LEN;

    if (p - data >= data_len) {
        g_debug("parse_tls_header: No se ha recibido un handshake completo");
        g_free(no_server_name);
        return NULL;
    }

    if (*p != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
        g_debug("parse_tls_header: No se ha recibido un client hello");
        g_free(no_server_name);
        return NULL;
    }

    /* Skip past:
       1	Handshake Type
       3	Length
       2	Version (again)
       32	Random
       to	Session ID Length
     */
    p += 38;
    if (p - data >= data_len) {
        g_debug("parse_tls_header: No se ha recibido un TLS handshake completo");
        g_free(no_server_name);
        return NULL;
    }

    len = (unsigned char)*p; /* Session ID Length */
    p += 1 + len; /* Skip session ID block */
    if (p - data >= data_len) {
        g_debug("parse_tls_header: No se ha recibido un TLS handshake completo");
        g_free(no_server_name);
        return NULL;
    }

    len = (unsigned char)*p << 8; /* Cipher Suites length high byte */
    p ++;
    if (p - data >= data_len) {
        g_debug("parse_tls_header: No se ha recibido un TLS handshake completo");
        g_free(no_server_name);
        return NULL;
    }
    len += (unsigned char)*p; /* Cipher Suites length low byte */

    p += 1 + len;

    if (p - data >= data_len) {
        g_debug("parse_tls_header: No se ha recibido un TLS handshake completo");
        g_free(no_server_name);
        return NULL;
    }
    len = (unsigned char)*p; /* Compression Methods length */

    p += 1 + len;


    if (p - data >= data_len) {
        g_debug("parse_tls_header: No hay extensiones presentes en el handshake");
        return no_server_name;
    }


    len = (unsigned char)*p << 8; /* Extensions length high byte */
    p++;
    if (p - data >= data_len) {
        g_debug("parse_tls_header: No se ha recibido un TLS handshake completo");
        g_free(no_server_name);
        return NULL;
    }
    len += (unsigned char)*p; /* Extensions length low byte */
    p++;

    while (1) {
        if (p - data + 4 >= data_len) { /* 4 bytes for the extension header */
            g_debug("parse_tls_header: Se acabaron las extensiones y no apareci'o el SNI");
            return no_server_name;
        }

        /* Parse our extension header */
        len = ((unsigned char)p[2] << 8) + (unsigned char)p[3]; /* Extension length */
        if (p[0] == 0x00 && p[1] == 0x00) { /* Check if it's a server name extension */
            /* There can be only one extension of each type, so we break
               our state and move p to beinging of the extension here */
            p += 4;
            if (p - data + len > data_len) {
                g_debug("parse_tls_header: No se ha recibido un TLS handshake completo");
                g_free(no_server_name);
                return NULL;
            }
            return parse_SNI(p, len);
        }
        p += 4 + len; /* Advance to the next extension header */
    }
    g_free(no_server_name);
    return NULL;
}

char *parse_SNI(const char* buf, int buf_len) {
    char* server_name;
    const char* p = buf;
    char name_type;
    int name_len;

    if (p - buf + 1 > buf_len) {
        g_debug("parse_tls_header: SNI incompleto");
        return NULL;
    }

    p += 2;

    while(1) {
        if (p - buf >= buf_len) {
            g_debug("parse_tls_header: SNI incompleto");
            return NULL;
        }
        name_type = *p;
        p ++;
        switch(name_type) {
            case(0x00):
                if (p - buf + 1 > buf_len) {
                    g_debug("parse_tls_header: SNI incompleto");
                    return NULL;
                }
                name_len = ((unsigned char)p[0] << 8) + (unsigned char)p[1];
                p += 2;
                if (p - buf + name_len > buf_len) {
                    g_debug("parse_tls_header: SNI incompleto");
                    return NULL;
                }
                if (name_len >= SERVER_NAME_LEN - 1) {
                    g_debug("parse_tls_header: nombre del servidor muy largo");
                    return NULL;
                }
                server_name = g_new0(char,SERVER_NAME_LEN);
                strncpy (server_name, p, name_len);
                server_name[name_len] = '\0';
                return server_name;
            default:
                g_debug("parse_tls_header: tipo de nombre desconocido en SNI");
        }
    }
}

/***************************************************************************************************/
/********************* funciones relacionadas con la conexión con el servidor ssl remoto ***********/

int initialize_openSSL(){
	
	//OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	SSL_library_init();
	
	global_extern_ssl_method = (SSL_METHOD*) SSLv23_client_method();

	if ((global_extern_ctx = SSL_CTX_new(global_extern_ssl_method)) == NULL){
		
		g_debug("initialize_openSSL: SSL_CTX_new failure: %s",ERR_error_string(ERR_get_error(),NULL));
		return -1;
	}
	return 0;
}

int connect_to_real_server(ssl_connection* s){
	
	int mi_fd, r, n;
	//GIOChannel* conn;
	GError* gerror = NULL;
	GSource *source;
	
	s->capture_status = 2;
	
/*********************************************************************************************************/
/*	Aqu'i tengo que hacer un ciclo que si me da error la creaci'on del socket lo vuelva a intentar
 * si se puede en funci'on del error que retorne la funcion socket, si no se puede limpiar estructuras
 * creadas y retornar -1*/
 
	mi_fd = socket( PF_INET, SOCK_STREAM, 0 );
	
	if (mi_fd == -1) {
    	g_message("connect_to_real_server: s = %u: fallo la creacion del socket con el servidor real: %m"\
					,s->secuence_number);
    	return -1;
	} else g_debug("connect_to_real_server: s = %u: se creo el socket %d para conexi'on con el servidor real"\
					,s->secuence_number, mi_fd);
/**********************************************************************************************************/	
	s->real_ssl_server_addr.sin_family = AF_INET;
    s->real_ssl_server_addr.sin_port   = htons(443);
    
    r = inet_aton( s->remote_ip, &(s->real_ssl_server_addr.sin_addr) );
    if (r == 0){
    	g_message("connect_to_real_server: s = %u: inet_aton failed: %m"\
					,s->secuence_number);
    	close(mi_fd);
    	return -1;
    }
    
    n = fcntl( mi_fd, F_GETFL, 0 );
    if (n == -1) {
		g_message("connect_to_real_server: s = %u: fcntl F_GETFL failure"\
					,s->secuence_number);
		return -1;
    }
    r = fcntl( mi_fd, F_SETFL, n | O_NONBLOCK);

	if (r == -1) {
		g_message("connect_to_real_server: s = %u: fcntl F_SETFL failure",\
					s->secuence_number);
    	return -1;
	}
	
	s->Channels_array[2]  = g_io_channel_unix_new(mi_fd);
    // Tengo que revisar aqu'i la posibilidad de que g_io_channel_unix_new falle, en cuyo caso tengo que hacer limpieza y retornar -1
    g_io_channel_set_encoding(s->Channels_array[2] ,NULL,&gerror);
    // Tengo que revisar aqu'i la posibilidad de que g_io_channel_set_encoding falle, en cuyo caso tengo que hacer limpieza y retornar -1
	g_io_channel_set_close_on_unref(s->Channels_array[2] ,TRUE);
	g_io_channel_set_buffer_size(s->Channels_array[2] ,0);
	
	//r = g_io_add_watch(s->Channels_array[2] ,(GIOCondition)(G_IO_IN | G_IO_OUT)G_IO_IN|G_IO_OUT,(GIOFunc)handle_ssl_connect,s);
	//r = g_io_add_watch(s->Channels_array[2] ,(GIOCondition)(G_IO_IN|G_IO_OUT),(GIOFunc)handle_ssl_connect,s);
	
	s->arreglo_source_ids[2] = g_io_add_watch_full(s->Channels_array[2] ,G_PRIORITY_DEFAULT,(GIOCondition)(G_IO_IN|G_IO_OUT),\
								(GIOFunc)handle_ssl_connect,s,(GDestroyNotify)destroy_ssl_conn);
	s->ref_count++;
	g_debug("connect_to_real_server: s = %u, ref_count = %u, adding handle_ssl_connect",s->secuence_number,s->ref_count);
	
	//g_message("connect_to_real_server: s = %u: salida de g_io_add_watch = %d",s->secuence_number,r);
	
	s->connect_atemp = 1;
	r = connect(mi_fd, (struct sockaddr *)&(s->real_ssl_server_addr),sizeof(s->real_ssl_server_addr));
	
	if (r == -1){

		switch(errno) {
		
		case EINPROGRESS:
			
			g_message("connect_to_real_server: s = %u: conexión con el servidor ssl en progreso",\
						s->secuence_number);
			break;
		case EALREADY:
			
			g_message("connect_to_real_server: s = %u: ya se está estableciendo la conexión con el servidor ssl"\
						,s->secuence_number);
			break;
			
		default:
			
			g_message("connect_to_real_server: s = %u: connect() failure",\
						s->secuence_number);
			
			// Aquí se le da shutdown al canal recientemente creado y se marca como removido de la estructura ssl_connection poniendo NULL
			// en la variable s->Channels_array[2]  para que cuando se libere la estructura completamente no se vuelva a intentar hacer eso.			
			g_io_channel_shutdown(s->Channels_array[2] ,FALSE,NULL);
			g_io_channel_unref(s->Channels_array[2] );
			s->Channels_array[2]  = NULL;
			
			// As the channel has been shut from a place other than the callback function that handle it, it's necessary to destroy the source
			// of events that represent it in the main_context. In the case of other channels (client_channel and internal_ssl_channel, their closure
			// is fatal to the hole MITM process, so after their are closed, the ssl_connection must be freed with the GDestroyNotify function (by means
			// of returning FALSE from a callback function or invoking it directly), but in the case of Channels_array[2]  it's closure is not fatal
			// so the ssl_connection does not need to be closed.
			
			source = g_main_context_find_source_by_id(NULL,s->arreglo_source_ids[2]);
			g_source_destroy(source);
			g_source_unref(source);
			
			s->ref_count--;
			g_debug("connect_to_real_server: s = %u, ref_count = %u, removing the external ssl channel because there was an early error in connect"\
					,s->secuence_number,s->ref_count);
			
			//s->arreglo_source_ids[2] = 0;
			return -1;
		}
	}
	return 0;   
}

gboolean handle_ssl_connect( GIOChannel *channel, GIOCondition cond,ssl_connection* s){
	
	if (s->Channels_array[2] != NULL) {
		
		if ((cond & G_IO_OUT) == G_IO_OUT){
		
			if (s->capture_status == 2){	// Si se está en la fase de establecimiento de la conexión con el servidor real.
						
				int r = connect(g_io_channel_unix_get_fd (channel),(struct sockaddr *)&(s->real_ssl_server_addr),sizeof(s->real_ssl_server_addr));
			
				g_message("handle_ssl_connect: s = %u: retorno de la función connect = %d",s->secuence_number,r);
				if (r == -1){
		
					switch(errno) {
						
					case EISCONN:
						
						//Aquí ya se estableció la conexión, proceder al handshake SSL
						g_message("handle_ssl_connect: s = %u: establecida la conexión con el servidor ssl"\
									,s->secuence_number);
						s->capture_status = 3;	// Ya está la conexión, mandamos a hacer el handshake
						
						if (SSL_iniciar_handshake(s) == -1){
							
							g_io_channel_shutdown(channel,FALSE,NULL);
							g_io_channel_unref(channel);
							s->Channels_array[2]  = NULL;
							s->ref_count--;
							
							g_debug("handle_ssl_connect: s = %u, ref_count = %u, exitting do to SSL_iniciar_handshake returned -1"\
									,s->secuence_number,s->ref_count);
							//s->arreglo_source_ids[2] = 0;
						
							// the fact that a connection with the real server could'nt be set does not means that the certificate can not
							// be created and that the MITM can't be stablished; so we call here create_own_certificate in order to do so.
							
							s->capture_status = 5;
							create_own_certificate(s);
		
							return FALSE;
						}
						break;
		
					case EINPROGRESS:
					
					case EALREADY:
						
						g_message("handle_ssl_connect: s = %u: estableciendose la conexión con el servidor ssl"\
									,s->secuence_number);
						break;
					
					case ETIMEDOUT:
						
						if (s->connect_atemp < 3){
							
							g_message("handle_ssl_connect: s = %u: timeout en la conexión con el servidor ssl"\
										,s->secuence_number);
							s->connect_atemp++;
							break;
						}
						else {
							
							g_message("handle_ssl_connect: s = %u: last timeout en la conexión con el servidor ssl"\
										,s->secuence_number);
						}
					default:
						
						g_message("handle_ssl_connect: s = %u: connect() failure",s->secuence_number);
						g_io_channel_shutdown(channel,FALSE,NULL);
						g_io_channel_unref(channel);
						s->Channels_array[2]  = NULL;
						s->ref_count--;
						g_debug("handle_ssl_connect: s = %u, ref_count = %u, exitting",s->secuence_number,s->ref_count);
						//s->arreglo_source_ids[2] = 0;
						
						// the fact that a connection with the real server could'nt be set does not means that the certificate can not
						// be created and that the MITM can't be stablished; so we call here create_own_certificate in order to do so.
						
						s->capture_status = 5;
						create_own_certificate(s);
						return FALSE;
					}
				}
				else {
					
					g_message("handle_ssl_connect: s = %u: establecida la conexión con el servidor ssl",\
								s->secuence_number);
					s->capture_status = 3;	// Ya está la conexión, mandamos a hacer el handshake
					
					if (SSL_iniciar_handshake(s) == -1){
						
						g_io_channel_shutdown(channel,FALSE,NULL);
						g_io_channel_unref(channel);
						s->Channels_array[2]  = NULL;
						s->ref_count--;
						g_debug("handle_ssl_connect: s = %u, ref_count = %u, exitting due to SSL_iniciar_handshake returned -1"\
								,s->secuence_number,s->ref_count);
						//s->arreglo_source_ids[2] = 0;
						
						s->capture_status = 5;
						create_own_certificate(s);
						return FALSE;
					}
				}
			}
			
			//if (s->capture_status == 3) return TRUE;	// Si se está esperando por el resultado del handshake aquí no hay nada más que hacer que 
														// dejar salir lo que sea.
			
		}
		
		if ((cond & G_IO_IN) == G_IO_IN) {
						
			X509 *m;
			int ret;
			gchar *buf2;
			gsize channel_size;
			
			channel_size = g_io_channel_get_buffer_size(channel);
			buf2 = g_new0( gchar, channel_size + 2 );
			
			// Chequeo de si es un error de entrada.
			
			ret = recv(g_io_channel_unix_get_fd(channel),buf2, channel_size,MSG_PEEK);
			g_debug("handle_ssl_connect: s = %u: caracteres peekeados con recv: %d",s->secuence_number, ret);
			g_free(buf2);
			
			if (ret < 1){
				
				if (s->capture_status == 3) {
						
					if (s->real_server_ssl != NULL)  SSL_free(s->real_server_ssl);
					s->real_server_ssl = NULL;
						
				}
				g_debug("handle_ssl_connect: s = %u: leaving with error in status = %u",s->secuence_number,s->capture_status);
				
				// Here we return, shutting down the channel and ceroing the reference to the source id because the is not point
				// in continuing the rest of the function because the data that can be received does not makes senses anymore.
				
				g_io_channel_shutdown(channel,FALSE,NULL);
				g_io_channel_unref(channel);
				s->Channels_array[2]  = NULL;
				s->ref_count--;
				g_debug("handle_ssl_connect: s = %u, ref_count = %u, exitting",s->secuence_number,s->ref_count);
				//s->arreglo_source_ids[2] = 0;
				
				// the fact that a connection with the real server could'nt be set does not means that the certificate can not
				// be created and that the MITM can't be stablished; so we call here create_own_certificate in order to do so.
				
				s->capture_status = 5;
				create_own_certificate(s);
				return FALSE;	
			}
			
			
			if ((s->capture_status == 3) && (s->real_server_ssl != NULL)) { // Si ya se está realizando el handshake con el servidor ssl real.
				
				g_debug("handle_ssl_connect: s = %u: ssl state = %s -- %s",\
					s->secuence_number,SSL_state_string(s->real_server_ssl),SSL_state_string_long(s->real_server_ssl));
				
				if ((SSL_is_init_finished(s->real_server_ssl)) || (SSL_state(s->real_server_ssl) == SSL3_ST_CR_FINISHED_A)\
							|| (SSL_state(s->real_server_ssl) == SSL3_ST_CR_FINISHED_B)){
				
					
					//Ya termino el handshake por lo tanto puedo extraer el certificado.
					g_debug("handle_ssl_connect: s = %u: terminado el handshake, extraemos el certificado",\
								s->secuence_number);
					
					s->capture_status = 4;
					
					m = ssl_extract_certificado(s);
			
					// Despu'es de extraido el certificado se termina la conexi'on ssl con el servidor real,
					// se limpian las estructuras necesarias.
					
					if (m == NULL) g_debug("handle_ssl_connect: s = %u: error extrayendo el certificado",\
												s->secuence_number);
					else g_debug("handle_ssl_connect: s = %u: se extrajo el certificado con exito",\
									s->secuence_number);
					
					// Aunque no se haya podido extraer el certificado eso no importa, pues se usa el SNI o la resoluci'on
					// DNS para generar el certificado.
			
					create_own_certificate(s);
			
					g_debug("handle_ssl_connect: s = %u: shutting down request fd = %d",\
					s->secuence_number,g_io_channel_unix_get_fd (channel));
					
					if (s->real_server_ssl != NULL)  SSL_free(s->real_server_ssl);
					s->real_server_ssl = NULL;
					g_io_channel_shutdown(channel,FALSE,NULL);
					g_io_channel_unref(channel);
					s->Channels_array[2]  = NULL;
					s->ref_count--;
					g_debug("handle_ssl_connect: s = %u, ref_count = %u, exitting",s->secuence_number,s->ref_count);
					//s->arreglo_source_ids[2] = 0;
					return FALSE;
				}
				else {
						
					SSL_do_handshake(s->real_server_ssl);
					//SSL_connect(s->real_server_ssl);
					g_debug("handle_ssl_connect: s = %u: aun no ha terminado el handshake",\
								s->secuence_number);
				}
			}
		}
		return TRUE;
	} 
	else {
		
		s->ref_count--;
		g_debug("handle_ssl_connect: s = %u, ref_count = %u, exitting",s->secuence_number,s->ref_count);
		return FALSE;
	}
}

int SSL_iniciar_handshake(ssl_connection* s){

	int ret;
	
	// Crear la estructura SSL
	if ((s->real_server_ssl = SSL_new(global_extern_ctx)) == NULL){

		g_message("SSL_iniciar_handshake: s = %u: SSL_new failure: %s",\
					s->secuence_number,ERR_error_string(ERR_get_error(),NULL));
		
		return -1;
	}
	SSL_set_options(s->real_server_ssl, SSL_OP_NO_COMPRESSION | SSL_OP_NO_TICKET | SSL_MODE_NO_AUTO_CHAIN);
	
	// Poner la estructura SSL en modo connect
	SSL_set_connect_state(s->real_server_ssl);
	
	// Agregar el SNI original a la estructura SSL
	if (s->SNI != NULL) {
		
		if (strcmp(s->SNI,"\0") != 0){
	
			SSL_set_tlsext_host_name(s->real_server_ssl,s->SNI);
		}
	}
	
	// Vincular la estructura SSL con el fd
	ret = SSL_set_fd(s->real_server_ssl,g_io_channel_unix_get_fd(s->Channels_array[2] ));
	if (ret == 0){
		g_debug("SSL_iniciar_handshake: s = %u: SSL_set_fd failure with error = %s",\
			s->secuence_number, ERR_error_string(ERR_get_error(),NULL));
		
    	if (s->real_server_ssl != NULL) SSL_free(s->real_server_ssl);
    	s->real_server_ssl = NULL;
    	
		return -1;
	}

	// Comenzar el handshake con el servidor ssl real
	ret = SSL_do_handshake(s->real_server_ssl);
	//ret = SSL_connect(s->real_server_ssl);
	
	g_debug("SSL_iniciar_handshake: s = %u: resultado inmediato de SSL_do_handshake = %d"\
				,s->secuence_number, ret);
	
	if (ret < 1){
		
		switch (SSL_get_error(s->real_server_ssl, ret)) {
			
			case SSL_ERROR_ZERO_RETURN:
			case SSL_ERROR_SYSCALL:
			case SSL_ERROR_SSL:
			
				g_debug("SSL_iniciar_handshake: s = %u: SSL_do_handshake return error: %s",\
					s->secuence_number,ERR_error_string(ERR_get_error(),NULL));
				
				//Revisar si aqui tengo que hacer SSL_shutdown, y como.
				
		    	if (s->real_server_ssl != NULL) SSL_free(s->real_server_ssl);
				return -1;
				break;
			
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
			
				g_debug("SSL_iniciar_handshake: s = %u: SSL_do_handshake return with WANT_SOMETHING",\
					s->secuence_number);

			default:
				break;	
		}	
	}
	// Si llegué hasta here it's because the handshake started, so I must stablish a timeout.
	s->arreglo_source_ids[4] = g_timeout_add_full(G_PRIORITY_DEFAULT,60000,(GSourceFunc)time_out_ssl_handshake,\
											s,(GDestroyNotify)destroy_ssl_conn);
	s->ref_count++;
	g_debug("SSL_iniciar_handshake: s = %u, ref_count = %u, adding time_out_ssl_handshake",s->secuence_number,s->ref_count);
	
	
	return 0;
}

gboolean time_out_ssl_handshake(ssl_connection* s) {
	
	GSource *source;
		
	if (s->capture_status < 4) {
	
		// Pasó un minuto entero (esto tengo que parametrizarlo) y no se ha terminado el proceso de conexi'on con el servidor
		// real, por lo tanto esto es un error.
		
		g_debug("time_out_ssl_handshake: s = %u: shutting down request fd = %d",\
			s->secuence_number,g_io_channel_unix_get_fd (s->Channels_array[2] ));
		
		if (s->real_server_ssl != NULL) SSL_shutdown(s->real_server_ssl);
		s->real_server_ssl = NULL;
		if (s->Channels_array[2]  != NULL) {
			
			//g_io_channel_shutdown(s->Channels_array[2] ,FALSE,NULL);
			//g_io_channel_unref(s->Channels_array[2] );
			//s->ref_count--;
			s->Channels_array[2] = NULL;
			
		}
		/*
		if (s->arreglo_source_ids[2] != 0) {
			
			source = g_main_context_find_source_by_id(NULL,s->arreglo_source_ids[2]);
			g_source_destroy(source);
			g_source_unref(source);
			
			s->arreglo_source_ids[2] = 0;
		}*/
		//s->arreglo_source_ids[4] = 0;
		
		// I have to check if, in this case, SSL_shutdown called from here triggers handle_ssl_handshake.
		// In order to do so I can fake an SSL server that never return nothing.
		
		// the fact that a connection with the real server could'nt be set does not means that the certificate can not
		// be created and that the MITM can't be stablished; so we call here create_own_certificate in order to do so.
		
		create_own_certificate(s);
		
	}
	s->ref_count--;
	g_debug("time_out_ssl_handshake: s = %u, ref_count = %u, exitting",s->secuence_number,s->ref_count);
	return FALSE;
}

X509* ssl_extract_certificado(ssl_connection* s){
	
	X509 *cert;
	//X509_NAME *subj;
	//X509_NAME_ENTRY *e;
	//ASN1_OBJECT *object;
	//ASN1_STRING *d;
	//int lastpos;
	
	cert = SSL_get_peer_certificate(s->real_server_ssl);
	
	if (cert == NULL) return NULL;
	
	s->real_server_certificate = (X509*)g_memdup(cert,sizeof(cert));
	
	return s->real_server_certificate;
	
	/*
	
	subj = X509_get_subject_name(cert);
	
	if (subj == NULL) return -1;
	
	//for (int i = 0; i < X509_NAME_entry_count(subj); i++) {
		
		//e = X509_NAME_get_entry(subj, i);
		
		lastpos = -1;
        for (;;){
			lastpos = X509_NAME_get_index_by_NID(subj, NID_commonName, lastpos);
			if (lastpos == -1) break;
		e = X509_NAME_get_entry(subj, lastpos);
		d = X509_NAME_ENTRY_get_data(e);
		
		g_debug("data = %s",ASN1_STRING_data(d));
	   
	//   }
		
		
		
		
		object = X509_NAME_ENTRY_get_object(e);
		
		i2d_ASN1_OBJECT(object, &p);
		g_debug("name = %s",p);
		
		d = X509_NAME_ENTRY_get_data(e);
		
		g_debug("data = %s",ASN1_STRING_data(d));
		//char *str = ASN1_STRING_data(d);
	}*/
}


/*************************************************** fin *******************************************/
/***************************************************************************************************/

void create_own_certificate(ssl_connection* s){
	
	// create_own_certificate usara g_spawn_async a un script que creara el certificado, cuando
	// se haya creado el certificado la funcion que se llama cuando termina el proceso child (set_certificate)
	// es la encargada de chequear que el certificado sea correcto y ponerlo donde va en la ssl_connection,
	// luego escribir lo que hay en el buffer y poner el puente entre el fd de afuera y el interno de openssl.
	
	g_debug("create_own_certificate: s = %u: creando el certificado",\
		s->secuence_number);
		
	/************************************** TEST *************************************************************/
	/* This should be removed because the bridge will be stablished in set_certificate ***********************/
	
	if (s->Channels_array[1]  == NULL) {
		
		s->capture_status = 6;
		int m = connect_to_internal_openssl(s);
		if (m == -1) {
			
			g_debug("set_certificate: no se pudo establecer conexi'on con openssl, abortando la conexi'on del cliente");
		
			s->mark_destroy = TRUE;
			s->Channels_array[0] = NULL;
			// Also we must mark every channel to be destroyed
			s->Channels_array[1] = NULL;
			s->Channels_array[2] = NULL;
			return;
		}
	}
	
	/************************************** END TEST **********************************************************/
	
	return;
}

void set_certificate(ssl_connection* s){	// This function is really a GChildWatchFunc that will be set with g_child_watch_add_full in
											// create own certificate, so it will have a GDestroyNotify function as well, and if the call to
											// connect_to_internal_openssl fails the only thing neccesary is to set mark_destroy to true and
											// in the GDestroyNotify the ssl_connection will be destroyed. In the case of this function, it's 
											// aparent in the documentation that as it's called just one time (when the child process exits)
											// it allways destroy it's source id when finish, that's why it's return type is void.
	
	int m;
	




	// Si todo salio bien poner el puente.
	
	if (s->Channels_array[1]  == NULL) {
		
		s->capture_status = 6;
		m = connect_to_internal_openssl(s);
		if (m == -1) {
			
			g_debug("set_certificate: no se pudo establecer conexi'on con openssl, abortando la conexi'on del cliente");
		
			s->mark_destroy = TRUE;
			s->Channels_array[0] = NULL;
			// Also we must mark every channel to be destroyed
			s->Channels_array[1] = NULL;
			s->Channels_array[2] = NULL;
			return;
		}
	}
	
	

	// Chequear aqu'i que la conexi'on con openssl este abierta antes de escribir algo en el socket

	//write (g_io_channel_unix_get_fd (s->Channels_array[1] ), s->buff->buffer,s->buff->tamanno);
	//fsync (g_io_channel_unix_get_fd (s->Channels_array[1] ));
	
	return;
}


/****************************************************************************************************/
/********************* funciones relacionadas con la conexión con el servidor ssl interno ***********/

int connect_to_internal_openssl(ssl_connection *s){
	
	int fd, r, n;
	GError* gerror = NULL;
	GSource* source;
		
	fd = socket( PF_INET, SOCK_STREAM, 0 );
	
	if (fd == -1) {
    	g_message("connect_to_internal_openssl: s = %u: socket failed: %m",s->secuence_number);
    	return -1;
	} else g_debug("connect_to_internal_openssl: s = %u: creado el socket %d para conexi'on con openssl",s->secuence_number,fd);
	
	s->internal_openssl_server_addr.sin_family = AF_INET;
    s->internal_openssl_server_addr.sin_port   = htons(5282);
    r = inet_aton( "127.0.0.1", &(s->internal_openssl_server_addr.sin_addr) );
    if (r == 0){
    	g_message("connect_to_internal_openssl: s = %u: inet_aton failed: %m",s->secuence_number);
    	return -1;
    }
	n = fcntl( fd, F_GETFL, 0 );
    if (n == -1) {
		g_message("connect_to_internal_openssl: s = %u: fcntl F_GETFL failure",s->secuence_number);
		return -1;
    }
	r = fcntl(fd, F_SETFL, n | O_NONBLOCK);
	if (r == -1) {
		g_message("connect_to_internal_openssl: s = %u: fcntl F_SETFL failure",s->secuence_number);
    	return -1;
	}
	// Revisar los posibles valores de retorno de las funciones de establecimiento del g_io_channel tal y como se aclara en
	// connect_to_real_server.
	s->Channels_array[1]  = g_io_channel_unix_new(fd);
    g_io_channel_set_encoding(s->Channels_array[1] ,NULL,&gerror);
	g_io_channel_set_close_on_unref(s->Channels_array[1] ,TRUE);
	g_io_channel_set_buffer_size(s->Channels_array[1] ,0);
	
	s->arreglo_source_ids[1] = g_io_add_watch_full(s->Channels_array[1] ,\
								G_PRIORITY_DEFAULT,(GIOCondition)(G_IO_IN|G_IO_ERR|G_IO_HUP),\
								(GIOFunc)handle_openssl_internal,s,(GDestroyNotify)destroy_ssl_conn);
								
	s->ref_count++;
	g_debug("connect_to_internal_openssl: s = %u, ref_count = %u, adding handle_openssl_internal",s->secuence_number,s->ref_count);
	
	s->arreglo_source_ids[6] = g_timeout_add_full(G_PRIORITY_DEFAULT,50,(GSourceFunc)timer_output_internal_channel,\
								s,(GDestroyNotify)destroy_ssl_conn);
	
	s->ref_count++;
	g_debug("connect_to_internal_openssl: s = %u, ref_count = %u, adding timer_output_internal_channel",s->secuence_number,s->ref_count);
	
	s->connect_atemp = 1;
	r = connect(fd, (struct sockaddr *)&(s->internal_openssl_server_addr),sizeof(s->internal_openssl_server_addr));
	
	if (r == -1){

		switch(errno) {
			
		case EISCONN:
			
			g_message("connect_to_internal_openssl: s = %u: establecida la conexión con el servidor openssl interno",\
							s->secuence_number);
			s->capture_status = 7;
					
			break;

		case EINPROGRESS:
			
			g_debug("connect_to_internal_openssl: s = %u: conexión con el servidor openssl interno en progreso",\
						s->secuence_number);
			break;
		case EALREADY:
			
			g_debug("connect_to_internal_openssl: s = %u: ya se está estableciendo la conexión con el servidor openssl interno"\
						,s->secuence_number);
			break;
			
		default:
			
			g_debug("connect_to_internal_openssl: s = %u: connect() failure",\
						s->secuence_number);

			g_io_channel_shutdown(s->Channels_array[1] ,FALSE,NULL);
			g_io_channel_unref(s->Channels_array[1] );
			s->Channels_array[1]  = NULL;
			
			source = g_main_context_find_source_by_id(NULL,s->arreglo_source_ids[1]);
			g_source_destroy(source);
			g_source_unref(source);
			//s->arreglo_source_ids[1] = 0;
			s->ref_count--;
			g_debug("connect_to_internal_openssl: s = %u, ref_count = %u, removing the internal openssl channel due to an early connect error"\
					,s->secuence_number,s->ref_count);
			
			source = g_main_context_find_source_by_id(NULL,s->arreglo_source_ids[6]);
			g_source_destroy(source);
			g_source_unref(source);
			s->arreglo_source_ids[6] = 0;
			s->ref_count--;
			g_debug(\
			"connect_to_internal_openssl: s = %u, ref_count = %u, removing the internal openssl channel output timer due to an early connect error"\
			,s->secuence_number,s->ref_count);
			
			return -1;
		}
	}
	return 0;
}

gboolean timer_output_internal_channel(ssl_connection* s) {
	
	if (s->Channels_array[1] != NULL) {
	
		if (s->capture_status == 6){	// Aún estamos en el proceso de conexión con el servidor openssl interno
		
			int r = connect(g_io_channel_unix_get_fd(s->Channels_array[1]),(struct sockaddr *)&(s->internal_openssl_server_addr),\
								sizeof(s->internal_openssl_server_addr));
			
			if (r == -1){
		
				switch(errno) {
					
				case EISCONN:
					
					// ver aclaraciones para este valor de errno en connect_to_real_server y determinar si proceden aquí.
					
					g_message("timer_output_internal_channel: s = %u: establecida la conexión con el servidor openssl interno",\
									s->secuence_number);
					//g_debug("timer_output_internal_channel: s = %u: 1a",s->secuence_number);
					s->capture_status = 7;
					//g_debug("timer_output_internal_channel: s = %u: 2a",s->secuence_number);
					
					break;
					
				case EINPROGRESS:
					
					g_debug("timer_output_internal_channel: s = %u: conexión con el servidor openssl en progreso",\
								s->secuence_number);
					break;
					
				case EALREADY:
					
					g_debug("timer_output_internal_channel: s = %u: ya se está estableciendo la conexión con el servidor openssl"\
								,s->secuence_number);
					break;
				
				case ETIMEDOUT:
					
					if (s->connect_atemp < 3){
						
						g_message("timer_output_internal_channel: s = %u: timeout en la conexión con el servidor openssl interno",\
									s->secuence_number);
						s->connect_atemp++;
						break;
					}
					else {
						
						g_message("timer_output_internal_channel: s = %u: last timeout en la conexión con el servidor openssl interno",\
									s->secuence_number);
					}
		
				default:
					
					g_message("timer_output_internal_channel: s = %u: connect() failure",\
								s->secuence_number);
					
					// Here I need to see if it's necessary to remove the channel and it's associated gsource, because as we 
					// are still connecting to the internal channel it's possible that handle_openssl_internal never triggers
					// without the connection and the source of event of the giochannel never get removed.
							
					//g_io_channel_shutdown(s->Channels_array[1],FALSE,NULL);
					//g_io_channel_unref(s->Channels_array[1]);
					s->Channels_array[1] = NULL;
					// Also we must mark every channel to be destroyed
					s->Channels_array[0] = NULL;
					s->Channels_array[2] = NULL;
					s->ref_count--;
					g_debug("timer_output_internal_channel: s = %u, ref_count = %u, exitting",s->secuence_number,s->ref_count);
					
					
					//s->arreglo_source_ids[1] = 0;
					//s->arreglo_source_ids[6] = 0;
					s->mark_destroy = TRUE;
					return FALSE;				
				}
			}
			else {
				
				g_message("timer_output_internal_channel: s = %u: establecida la conexión con el servidor openssl interno",\
								s->secuence_number);
				//g_debug("timer_output_internal_channel: s = %u: 1b",s->secuence_number);
				s->capture_status = 7;
				//g_debug("timer_output_internal_channel: s = %u: 2b",s->secuence_number);
			}
		}
		else if (s->capture_status == 7) {	// Ya estamos conectados, por lo tanto se activa la cola.
			
			struct ssl_buffer* buffer_a_enviar = NULL;
			if (s->ssl_queue->just_sended == NULL) {
				
				if (s->ssl_queue->first != NULL) {
						
						buffer_a_enviar = s->ssl_queue->first;
						g_debug("timer_output_internal_channel: s = %u: sending to the openssl internal the first buffer of the queue"\
						,s->secuence_number);
				}
				else return TRUE;
	
			}
			else if (s->ssl_queue->just_sended->next == NULL) return TRUE;
			else buffer_a_enviar = s->ssl_queue->just_sended->next;
			
			int ret = write(g_io_channel_unix_get_fd(s->Channels_array[1]),buffer_a_enviar->buffer,buffer_a_enviar->tamanno);
			
			if (ret == (ssize_t)(buffer_a_enviar->tamanno)){
					
				// Se escribió todo el buffer (lo que deberá ocurrir la mayoría de las veces).
				
				g_message("timer_output_internal_channel: s = %u: enviado un buffer al servidor interno",s->secuence_number);
				
				s->ssl_queue->just_sended = buffer_a_enviar;
				
				if ( s->ssl_queue->just_sended->previous != NULL) {
					
					g_free(s->ssl_queue->just_sended->previous->buffer);
					g_free(s->ssl_queue->just_sended->previous);
					s->ssl_queue->just_sended->previous = NULL;
					
				}
			}
			else if (ret == -1){
			
				switch (errno){
					
				case EAGAIN:
					
					//tengo que abundar en la documentación de esto.
					
					g_message("timer_output_internal_channel: s = %u: se envió un buffer al servidor openssl interno con EAGAIN",\
									s->secuence_number);
					
					/*s->ssl_queue->just_sended = buffer_a_enviar;
				
					if ( s->ssl_queue->just_sended->previous != NULL) {
						
						g_free(s->ssl_queue->just_sended->previous->buffer);
						g_free(s->ssl_queue->just_sended->previous);
						s->ssl_queue->just_sended->previous = NULL;
						
					}*/
					break;
					
				case EINTR:
					
					// This means that the write operation was interrupted by a signal sended to the program, so it's necessary to repeat the
					// operation. The use of the macro TEMP_FAILURE_RETRY is not convenient here because if the condition that generated the
					// signal is not solved (somehow ?) this could lead to an infinite cycle that blocks the program. Any way, as this function
					// is a callback for the GIOChannel that is called when the Channel can accept output operations it is enough to return TRUE
					// here in order to repeat the write operation later.
					
					g_message("timer_output_internal_channel: s = %u: write returned with EINTR",\
									s->secuence_number);
				
					break;
					
				default:
				
					// Otro tipo de error, hay que cancelar la conexión del cliente.
					
					g_message("timer_output_internal_channel: s = %u: error en la escritura de un buffer al servidor openssl interno",\
									s->secuence_number);
					
					buffer_a_enviar->write_tries++;
					
					if (buffer_a_enviar->write_tries > 10) {
						
						g_message("timer_output_internal_channel: s = %u: timeout en la escritura de un buffer al servidor openssl interno, aborting..",\
									s->secuence_number);
									
						//g_io_channel_shutdown(s->Channels_array[1],FALSE,NULL);
						//g_io_channel_unref(s->Channels_array[1]);
						s->Channels_array[1]  = NULL;
						// Also we must mark every channel to be destroyed
						s->Channels_array[0] = NULL;
						s->Channels_array[2] = NULL;
						s->ref_count--;
					
						//s->arreglo_source_ids[1] = 0;
						
						// Tengo que eliminar el gsource del channel interno
						
						//s->arreglo_source_ids[6] = 0;
						//s->ref_count--;
						s->mark_destroy = TRUE;
						return FALSE;
					}
					break;
				}
			}
			else if ((ret > 0) && (ret < (ssize_t)(buffer_a_enviar->tamanno))){
						
				g_message("timer_output_internal_channel: s = %u: no se terminó de escribir un buffer al servidor openssl interno",\
									s->secuence_number);
			
				buffer_a_enviar->buffer = buffer_a_enviar->buffer + ret;
				buffer_a_enviar->tamanno = buffer_a_enviar->tamanno - ret;
			}
		}
	}
	else {
		
		s->ref_count--;
		g_debug("timer_output_internal_channel: s = %u, ref_count = %u, exitting",s->secuence_number,s->ref_count);
		return FALSE;
	}
}

gboolean handle_openssl_internal( GIOChannel *channel, GIOCondition cond, ssl_connection *s){
	
	if ((cond & G_IO_ERR) == G_IO_ERR){
		
		g_debug("handle_openssl_internal: s = %u: G_IO_ERR",s->secuence_number);
		s->ref_count--;
		g_debug("handle_openssl_internal: s = %u, ref_count = %u, exitting due to an error",s->secuence_number,s->ref_count);
		return FALSE;
	}
	if ((cond & G_IO_HUP) == G_IO_HUP){
		
		g_debug("handle_openssl_internal: s = %u: G_IO_HUP",s->secuence_number);
		s->ref_count--;
		g_debug("handle_openssl_internal: s = %u, ref_count = %u, exitting due to an error",s->secuence_number,s->ref_count);
		return FALSE;
	}
	
	
	//g_debug("handle_openssl_internal: entering 00000");
	if (s->Channels_array[1] != NULL) {
		
		//g_debug("handle_openssl_internal: s = %u: entering",s->secuence_number);
	
		if ((cond & G_IO_IN) == G_IO_IN){
			
			//if (s->capture_status == 7){	// Esto es por si las moscas, pero realmente no hace falta pues el servidor interno
												// no enviará ninguna información hasta que no se haya establecido la conexión de los
												// sockets.
				//g_debug("handle_openssl_internal: s = %u: 3a",s->secuence_number);
				gsize channel_size;
				gchar *buf;
				GIOStatus r;
				guint n;
				//gint m;
				GError* gerror = NULL;
				//GSource *source;
				
				channel_size = g_io_channel_get_buffer_size(channel);
				buf = g_new0( gchar, channel_size + 2 );
				r = g_io_channel_read_chars(channel, buf, channel_size, &n,&gerror);
				
				if ((gerror != NULL) || (n == 0)) {
			
					if (gerror != NULL) g_debug("handle_openssl_internal: s = %u: g_io_channel_read_chars return error: %s"\
						,s->secuence_number,gerror->message);
					else g_debug("handle_openssl_internal: s = %u: g_io_channel_read_chars connection closed by the internal openssl server"\
						,s->secuence_number);
					g_free(buf);
					
					g_io_channel_shutdown(channel,FALSE,NULL);
					g_io_channel_unref(channel);
					s->Channels_array[1]  = NULL;
					// Also we must mark every channel to be destroyed
					s->Channels_array[0] = NULL;
					s->Channels_array[2] = NULL;
					s->ref_count--;
					g_debug("handle_openssl_internal: s = %u, ref_count = %u, exitting due to an error",s->secuence_number,s->ref_count);
					
					//s->arreglo_source_ids[1] = 0;
					s->mark_destroy = TRUE;
					return FALSE;
				}
				
				struct ssl_buffer* my_buffer = g_new0(struct ssl_buffer,1);
				my_buffer->tamanno = n;
				my_buffer->buffer = g_strdup(buf);
				my_buffer->next = NULL;
				my_buffer->previous = NULL;
				my_buffer->write_tries = 0;
				
				if (s->ssl_queue_r->last == NULL) inicialize_queue(s->ssl_queue_r,buf,n);
				else insert_in_queue(s->ssl_queue_r,my_buffer);
		
				g_free(buf);
			//}
		}
		//g_debug("handle_openssl_internal: s = %u: leaving",s->secuence_number);
		return TRUE;
	}
	else {
		s->ref_count--;
		g_debug("handle_openssl_internal: s = %u, ref_count = %u, exitting",s->secuence_number,s->ref_count);
		return FALSE;
	}
}

void llenar_first_buffer(ssl_connection *s,gchar* buf,guint n){
	
	gchar* tempo;

	//g_debug("llenar_first_buffer: entrando para llenar el buffer: %u", h->ssl_buff);
	//g_debug("llenar_first_buffer: tamanno = %u", h->ssl_buff->tamanno);
	//g_debug("llenar_first_buffer: %s", h->ssl_buff->buffer);
	
	if (s->ssl_queue->last == NULL) inicialize_queue(s->ssl_queue,buf,n);
	else {
		
		tempo = g_new0(gchar,s->ssl_queue->last->tamanno + n);
		memcpy(tempo,s->ssl_queue->last->buffer,s->ssl_queue->last->tamanno);
		memcpy(tempo + s->ssl_queue->last->tamanno, buf,n);
		s->ssl_queue->last->tamanno = s->ssl_queue->last->tamanno + n;
		g_free(s->ssl_queue->last->buffer);
		s->ssl_queue->last->buffer = tempo;
	}
	return;
}

void inicialize_queue(struct queue* the_queue,gchar* buf,guint n){
	
	struct ssl_buffer* buffer = g_new0(struct ssl_buffer,1);
	
	buffer->next = NULL;
	buffer->previous = NULL;
	buffer->buffer = g_new0(gchar,n);
	memcpy(buffer->buffer,buf,n);
	buffer->tamanno = n;
	buffer->write_tries = 0;
	
	the_queue->first = buffer;
	the_queue->last = buffer;
	
	return;
}

void insert_in_queue(struct queue* the_queue,struct ssl_buffer* buffer_to_include){
	
	// The queue is garanteed that will always have at least one element that is at the end, so this function only need to add the 
	// recently arrived buffer to the end of the queue by means of pointing the "next" field of the last element of the queue to it.
	
	buffer_to_include->previous = the_queue->last;
	the_queue->last->next = buffer_to_include;
	the_queue->last = buffer_to_include;
}

void remove_buffer(struct ssl_buffer* buffer){
	
	if (buffer->previous != NULL) remove_buffer(buffer->previous);
	g_free(buffer->buffer);
	g_free(buffer);
	return;
}

void delete_queue(struct queue* the_queue){
	
	if (the_queue->last != NULL) remove_buffer(the_queue->last);
	g_free(the_queue);
	return;
}

/*************************************************** fin *******************************************/
/***************************************************************************************************/


