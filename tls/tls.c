//# include "tls.h"
# include "http.h"

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

/* Send a TLS handshake failure alert and close a socket */
void
close_tls_socket(int sockfd) {
    send(sockfd, tls_alert, sizeof(tls_alert), 0);
    close(sockfd);
}

/* Parse a TLS packet for the Server Name Indication extension in the client hello
 * handshake, returning the first servername found (pointer to static array) */
char *parse_tls_header(const char* data, int data_len) {
	
/* Esta funci'on devuelve los siguientes valores:
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
            return parse_server_name_extension(p, len);
        }
        p += 4 + len; /* Advance to the next extension header */
    }
    return NULL;
}

char *
parse_server_name_extension(const char* buf, int buf_len) {
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

int connect_to_real_server(http_request *h){
	
	//SSL_METHOD *mi_metodo_ssl;
	//SSL_CTX *mi_ctx;
	int mi_fd, r;
	struct sockaddr_in server;
	//GIOChannel* conn;
	GError* gerror = NULL;
	
	h->ssl_capture_status = 2;
	
	//mi_metodo_ssl = (SSL_METHOD*) SSLv23_client_method();
	
	/*if ((mi_ctx = SSL_CTX_new(mi_metodo_ssl)) == NULL){
		
		g_debug("connect_to_real_server: fd = %d: SSL_CTX_new failure: %s",g_io_channel_unix_get_fd (h->sock),ERR_error_string(ERR_get_error(),NULL));
		// Revisar si tengo que limpiar algo antes de retornar con error.
		return -1;
	}*/
	if ((h->real_server_ssl = SSL_new(global_extern_ctx)) == NULL){
		
		g_debug("connect_to_real_server: fd = %d: SSL_new failure: %s",g_io_channel_unix_get_fd (h->sock),ERR_error_string(ERR_get_error(),NULL));
		
		//if (mi_ctx != NULL) SSL_CTX_free(mi_ctx);
		return -1;
	}
	
	SSL_set_connect_state(h->real_server_ssl);
	
	if (h->ssl_server_name_extension != NULL) {
		
		if (strcmp(h->ssl_server_name_extension,"\0") != 0){
	
			SSL_set_tlsext_host_name(h->real_server_ssl,h->ssl_server_name_extension);
		}
	} 

/*********************************************************************************************************/
/*	Aqu'i tengo que hacer un ciclo que si me da error la creaci'on del socket lo vuelva a intentar
 * si se puede en funci'on del error que retorne la funcion socket, si no se puede limpiar estructuras
 * creadas y retornar -1*/
 
	mi_fd = socket( PF_INET, SOCK_STREAM, 0 );
	
	if (mi_fd == -1) {
    	g_message("connect_to_real_server: fd = %d: fallo la creacion del socket con el servidor real: %m",g_io_channel_unix_get_fd (h->sock));
    	if (h->real_server_ssl != NULL) SSL_free(h->real_server_ssl);
    	//if (mi_ctx != NULL) SSL_CTX_free(mi_ctx);
    	return -1;
	} else g_debug("connect_to_real_server: fd = %d: se creo el socket %d para conexi'on con el servidor real",g_io_channel_unix_get_fd (h->sock), mi_fd);
/**********************************************************************************************************/	
	server.sin_family = AF_INET;
    server.sin_port   = htons(443);
    
    r = inet_aton( h->ssl_remote_ip, &(server.sin_addr) );
    if (r == 0){
    	g_message("connect_to_real_server: fd = %d: inet_aton failed: %m",g_io_channel_unix_get_fd (h->sock));
    	close(mi_fd);
    	if (h->real_server_ssl != NULL) SSL_free(h->real_server_ssl);
    	//if (mi_ctx != NULL) SSL_CTX_free(mi_ctx);
    	return -1;
    }
	r = connect(mi_fd, (struct sockaddr *)&(server),sizeof(server));
	
	if (r == -1){
    	g_message("connect_to_real_server: fd = %d: connect failed on file descriptor %d: %m",g_io_channel_unix_get_fd (h->sock), mi_fd);
    	close(mi_fd);
    	if (h->real_server_ssl != NULL) SSL_free(h->real_server_ssl);
    	//if (mi_ctx != NULL) SSL_CTX_free(mi_ctx);
    	return -1;
    }
    r = fcntl( mi_fd, F_GETFL, 0 );
	fcntl( mi_fd, F_SETFL, r | O_NONBLOCK);
	
    h->ssl_external_sock = g_io_channel_unix_new(mi_fd);
    // Tengo que revisar aqu'i la posibilidad de que g_io_channel_unix_new falle, en cuyo caso tengo que hacer limpieza y retornar -1
    g_io_channel_set_encoding(h->ssl_external_sock,NULL,&gerror);
    // Tengo que revisar aqu'i la posibilidad de que g_io_channel_set_encoding falle, en cuyo caso tengo que hacer limpieza y retornar -1
	g_io_channel_set_close_on_unref(h->ssl_external_sock,TRUE);
	g_io_channel_set_buffer_size(h->ssl_external_sock,0);
	
	g_io_add_watch(h->ssl_external_sock, G_IO_IN,(GIOFunc)handle_ssl_handshake, h);
	// Tengo que revisar aqu'i la posibilidad de que g_io_add_watch falle, en cuyo caso tengo que hacer limpieza y retornar -1
	
	r = SSL_set_fd(h->real_server_ssl,mi_fd);
	if (r == 0){
		g_debug("connect_to_real_server: fd = %d: SSL_set_fd failure with error = %s",g_io_channel_unix_get_fd (h->sock), ERR_error_string(ERR_get_error(),NULL));
		//g_io_channel_unref(conn);
		g_io_channel_unref(h->ssl_external_sock);
		g_io_channel_shutdown(h->ssl_external_sock,FALSE,NULL);
		//close(mi_fd);
    	if (h->real_server_ssl != NULL) SSL_free(h->real_server_ssl);
    	//if (mi_ctx != NULL) SSL_CTX_free(mi_ctx);
		return -1;
	}
	
	r = SSL_do_handshake(h->real_server_ssl);
	
	g_debug("connect_to_real_server: fd = %d: resultado inmediato de SSL_do_handshake = %d",g_io_channel_unix_get_fd (h->sock), r);
	
	if (r < 1){
		
		switch (SSL_get_error(h->real_server_ssl, r)) {
			
			case SSL_ERROR_ZERO_RETURN:
			case SSL_ERROR_SYSCALL:
			case SSL_ERROR_SSL:
			
				g_debug("connect_to_real_server: fd = %d: SSL_do_handshake return error: %s",g_io_channel_unix_get_fd (h->sock),ERR_error_string(ERR_get_error(),NULL));
				
				//Revisar si aqui tengo que hacer SSL_shutdown, y como.
				
				//g_io_channel_unref(conn);
				g_io_channel_unref(h->ssl_external_sock);
				g_io_channel_shutdown(h->ssl_external_sock,FALSE,NULL);
				//close(mi_fd);
		    	if (h->real_server_ssl != NULL) SSL_free(h->real_server_ssl);
		    	//if (mi_ctx != NULL) SSL_CTX_free(mi_ctx);
				return -1;
			
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
			
				g_debug("connect_to_real_server: fd = %d: SSL_do_handshake return with WANT_SOMETHING",g_io_channel_unix_get_fd (h->sock));
				//break;
			default:
				break;
				
		}
		
	}
	
	g_timeout_add( 60000, (GSourceFunc) time_out_ssl_handshake, h);
	return 0;
}

gboolean handle_ssl_handshake( GIOChannel *sock, GIOCondition cond, http_request *h ) {

	X509 *m;
	int ret;
	gchar *buf2;
	gsize channel_size;
	
	channel_size = g_io_channel_get_buffer_size(sock);
	buf2 = g_new0( gchar, channel_size + 2 );
	ret = recv(g_io_channel_unix_get_fd(sock),buf2, channel_size,MSG_PEEK);
	g_debug("handle_ssl_handshake: fd = %d: caracteres peekeados con recv: %d",g_io_channel_unix_get_fd (h->sock), ret);
	g_free(buf2);
	
	if (ret == 0){
		
		g_debug("handle_ssl_handshake: fd = %d: leaving with error..",g_io_channel_unix_get_fd (h->sock));
		SSL_free(h->real_server_ssl);
		g_io_channel_unref(sock);
		g_io_channel_shutdown(sock,TRUE,NULL);
		return FALSE;
	}
	
	g_debug("handle_ssl_handshake: fd = %d: ssl state = %s",g_io_channel_unix_get_fd (h->sock),SSL_state_string_long(h->real_server_ssl));
	
	ret = SSL_get_shutdown(h->real_server_ssl);
	
	switch(ret) {
		
	case 0:
	    
	    if (SSL_is_init_finished(h->real_server_ssl)){
		
			//Ya termino el handshake por lo tanto puedo extraer el certificado.
			g_debug("handle_ssl_handshake: fd = %d: terminado el handshake, extraemos el certificado",g_io_channel_unix_get_fd (h->sock));
			
			h->ssl_capture_status = 3;
			
			m = ssl_extract_certificado(h);
			
			// Despu'es de extraido el certificado se termina la conexi'on ssl con el servidor real,
			// se limpian las estructuras necesarias.
			
			if (m == NULL) g_debug("handle_ssl_handshake: fd = %d: error extrayendo el certificado",g_io_channel_unix_get_fd (h->sock));
			
			// Aunque no se haya podido extraer el certificado eso no importa, pues se usa el SNI o la resoluci'on
			// DNS para generar el certificado.
			
			g_timeout_add(100, (GSourceFunc) create_own_certificate, h);
			
			ret = SSL_shutdown(h->real_server_ssl);
			
			g_debug("handle_ssl_handshake: fd = %d: salida de SSL_shutdown = %d",g_io_channel_unix_get_fd (h->sock),ret);
			
			if (ret == 1){
				
				//Perform cleaning of all the structures used in the SSL connection.
				return FALSE;
			}
			
			return FALSE;
		}
		else {
			
			SSL_do_handshake(h->real_server_ssl);
			g_debug("handle_ssl_handshake: fd = %d: aun no ha terminado el handshake",g_io_channel_unix_get_fd (h->sock));
		}
	    break;
	    
	case SSL_RECEIVED_SHUTDOWN:
	
		g_debug("handle_ssl_handshake: fd = %d: recibida la respuesta al shutdown",g_io_channel_unix_get_fd (h->sock));
		//Limpiar todo.
		return FALSE;
	    
	    break;
	case SSL_SENT_SHUTDOWN:
	
		g_debug("handle_ssl_handshake: fd = %d: shutting down request fd = %d",g_io_channel_unix_get_fd (h->sock),g_io_channel_unix_get_fd (sock));
		SSL_free(h->real_server_ssl);
		g_io_channel_unref(sock);
		g_io_channel_shutdown(sock,TRUE,NULL);
		return FALSE;
		
	default:
		
		break;
    }
	return TRUE;
}

gboolean time_out_ssl_handshake( http_request *h ) {
	
	if (h != NULL) {
		
		if (h->ssl_capture_status < 3) {
		
			// Paso un minuto entero (esto tengo que parametrizarlo) y no se ha terminado el proceso de conexi'on con el servidor
			// real, por lo tanto esto es un error.
			
			g_debug("time_out_ssl_handshake: fd = %d: shutting down request fd = %d",g_io_channel_unix_get_fd (h->sock),g_io_channel_unix_get_fd (h->ssl_external_sock));
			
			SSL_shutdown(h->real_server_ssl);
			
			// I have to check here if, in this case, SSL_shutdown called from here triggers handle_ssl_handshake.
			// In order to do so I can fake an SSL server that never return nothing.
			
			// the fact that a connection with the real server could'nt be set does not means that the certificate can not
			// be created and that the MITM can't be stablished; so we call here create_own_certificate in order to do so.
			
			g_timeout_add(100, (GSourceFunc) create_own_certificate, h);
		}
		
	}
	/*else {
		
		// Esto lo que puede significar es que ya se completo el proceso de autentificacion
		// por lo tanto este time out esta de mas, retornando false lo eliminamos. No hay necesidad
		// de hacer ningun tipo de limpieza pues se supone que cuando se elimin'o el http_request se
		// hizo todo lo adecuado.
		
		return FALSE;
	}*/
	
	return FALSE;
}

X509* ssl_extract_certificado(http_request *h){
	
	X509 *cert;
	//X509_NAME *subj;
	//X509_NAME_ENTRY *e;
	//ASN1_OBJECT *object;
	//ASN1_STRING *d;
	//int lastpos;
	
	cert = SSL_get_peer_certificate(h->real_server_ssl);
	
	if (cert == NULL) return NULL;
	
	h->real_server_certificate = (X509*)g_memdup(cert,sizeof(cert));
	
	return h->real_server_certificate;
	
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

gboolean create_own_certificate(http_request *h){
	
	// create_own_certificate usara g_spawn_async a un script que creara el certificado, cuando
	// se haya creado el certificado la funcion que se llama cuando termina el proceso child (set_certificate)
	// es la encargada de chequear que el certificado sea correcto y ponerlo donde va en el http_request,
	// luego escribir lo que hay en el buffer y poner el puente entre el fd de afuera y el interno de openssl.
	
	h->ssl_capture_status = 4;

	return FALSE;
}

void set_certificate(http_request *h){
	
	int m;
	
	
	
	
	// Si todo salio bien poner el puente.
	
	h->ssl_capture_status = 5;
			
	if (h->ssl_server_fd == 0) {
	
		m = connect_to_internal_openssl(h);
		if (m == -1) {
			
		g_debug("set_certificate: no se pudo establecer conexi'on con openssl, abortando la conexi'on del cliente");
		
		// Tomar medidas aqu'i para tumbar la conexi'on del cliente y todo lo asociado a ella.
		}
	}

	// Chequear aqu'i que la conexi'on con openssl este abierta antes de escribir algo en el socket

	write (h->ssl_server_fd, h->ssl_buff->buffer,h->ssl_buff->tamanno);
	fsync (h->ssl_server_fd);
	
	return;
}

int connect_to_internal_openssl(http_request *h){
	
	int r;
	GIOChannel* conn;
	struct sockaddr_in server_addr;
	GError* gerror = NULL;
		
	h->ssl_server_fd = socket( PF_INET, SOCK_STREAM, 0 );
	
	if (h->ssl_server_fd == -1) {
    	g_message("connect_to_internal_openssl: socket failed: %m");
    	return -1;
	} else g_debug("connect_to_internal_openssl: creado el socket %d para conexi'on con openssl",h->ssl_server_fd);
	
	server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(5282);
    r = inet_aton( "127.0.0.1", &(server_addr.sin_addr) );
    if (r == 0){
    	g_message("connect_to_internal_openssl: inet_aton failed: %m");
    	return -1;
    }

	r = connect(h->ssl_server_fd, (struct sockaddr *)&(server_addr),sizeof(server_addr));
	
	if (r == -1){
    	g_message("connect_to_internal_openssl: connect failed on %d: %m", h->ssl_server_fd);
    	return -1;
    }
    r = fcntl( h->ssl_server_fd, F_GETFL, 0 );
	fcntl( h->ssl_server_fd, F_SETFL, r | O_NONBLOCK);
	
    conn = g_io_channel_unix_new(h->ssl_server_fd);
    g_io_channel_set_encoding(conn,NULL,&gerror);
	g_io_channel_set_close_on_unref(conn,TRUE);
	g_io_channel_set_buffer_size(conn,0);
	
	g_io_add_watch(conn, G_IO_IN,(GIOFunc)handle_write_ssl, h);
	
	return 0;
}

/************* Https Write Output Data Connection handle *******/

gboolean handle_write_ssl( GIOChannel *sock, GIOCondition cond, http_request *h ) {
	
	g_debug("handle_write_ssl: reading request fd = %d",g_io_channel_unix_get_fd (sock));
	
	gsize channel_size;
	gchar *buf;
	GIOStatus r;
	guint n;
	GError* gerror = NULL;
	//GIOChannel* conn;
	
	channel_size = g_io_channel_get_buffer_size(sock);
	buf = g_new0( gchar, channel_size + 2 );
	r = g_io_channel_read_chars(sock, buf, channel_size, &n,&gerror);
	if (gerror != NULL) {
				
		g_message("handle_write_ssl: g_io_channel_read_chars return error: %s",gerror->message);
		g_free(buf);
		return FALSE;
	}
	
	if (n == 0){

		g_free(buf);
		g_debug("handle_write_ssl: leaving with error..");
		return FALSE;
	}
	
	g_debug("handle_write_ssl: caracteres leidos: %u", n);
	//g_debug("handle_write_ssl: %s", buf);
	
	write (h->outside_fd, buf,n);
	fsync (h->outside_fd);
	
	g_debug("handle_write_ssl: caracteres escritos: %u", n);
	g_free(buf);
	//close (fd_c);

	return TRUE;
}

