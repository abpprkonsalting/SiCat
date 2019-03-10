# include <glib.h>
# include <string.h>
# include <stdio.h>
# include <netinet/in.h>
# include <sys/socket.h>
# include <sys/types.h>
# include <sys/wait.h>
# include <unistd.h>
//# include "gateway.h"
# include "websck.h"

/*struct redirect{
	
	http_request* h;
	GString* dest;
};*/

extern class comm_interface* wsk_comm_interface;
extern gchar* macAddressFrom;
//extern class files_array* clients_fw_files_array;
//struct redirect* redire;

/*gboolean redirecciona( GIOChannel *channel, GIOCondition cond, struct redirect* redire){
	
	//http_send_redirect(redire->h, redire->dest->str);
	//g_string_free( redire->dest, 1 );
	
	//clients_fw_files_array->remove_chann(channel);
	g_message("yes");
	
	return TRUE;
}*/

void capture_peer ( http_request *h, peer *p ) {
	
    /* Esta función lo que hace es enviar al usuario que se está conectando un http redirect
     * para que vuelva a enviar la petición http pero esta vez dirigida al servidor auth */
    
    gchar* redir = target_redirect( h );
    //gchar* gw_addr = local_host( h );
    GHashTable* args = g_hash_new();
    GString* dest;

    g_hash_set( args, "redirect",	redir );
    g_hash_set( args, "usertoken",	get_peer_token(p) );
    g_hash_set( args, "userMac",    p->hw );
    g_hash_set( args, "deviceMac",	macAddressFrom);
    //g_hash_set( args, "timeout",	CONF("LoginTimeout") );
    //g_hash_set( args, "gateway",	gw_addr );

    dest = build_url( CONF("AuthServiceURL"), args );

	// Antes de enviarle la redirección al cliente debo garantizar que el websocket está abierto 
	// para recibir la respuesta. Esto se hace enviando un comando NULL a través de la interface
	// del websocket. Si el websocket está activo esto no hace nada, si está cerrado lo abre y 
	// envía un comando init.
	
	// Esto tengo que arreglarlo, pues llamar wsk_send_command no garantiza que el websocket se haya
	// establecido correctamente. Además, en función de si el wsk se estableció o no debo enviarle
	// al usuario el redirect o una página informándole del error de conexión con el servidor y 
	// que contacte a la administración, etc..
	
	// Todos los comentarios anteriores no son válidos. Al cliente se le envía la redirección esté
	// o no abierto el wsk. El proceso de autentificación en el servidor es quien se debe encargar
	// de no decirle al usuario que ya tiene internet libre hasta que reciba confirmación desde el
	// dispositivo de que esa acción se realizó. La línea de abajo solo tiene el objetivo de inicializar
	// el websocket en caso de que esté inactivo, para tratar de garantizar que el servidor tenga
	// como enviar la autorización del usuario. 
	
	wsk_comm_interface->wsk_send_command(NULL,NULL,NULL);
	
	/*char* file_name = (char*)calloc(1,100);
	strcpy(file_name,(char*)"/var/log/access_fw_client_");
	strcat(file_name,p->hw);
	strcat(file_name,(char*)".log");
	
	int fd = open(file_name, O_RDONLY | O_CREAT);
	
	if (fd != -1) {
		
		clients_fw_files_array->add_file(fd);
		
		redire = g_new0(struct redirect,1);
		redire->h = h;
		redire->dest = dest; 
		g_io_add_watch(clients_fw_files_array->get_item(fd), G_IO_IN, (GIOFunc) redirecciona,redire);
	}*/
	
	if (p->status != 2) {
		p->status = 2;
		g_message("peer en proceso de autentificación, permitiendolo por 3 minutos...");
		peer_permit ( nocat_conf, p,h,dest );
	}

//***********************************************************************************************
	/*Added lines by abp*/

	gint fid = g_io_channel_unix_get_fd(h->sock);
	struct sockaddr_in remote_socket;	
	socklen_t n = sizeof(struct sockaddr_in);

	getpeername (fid, (struct sockaddr *)&remote_socket,  &n );

	g_message( "Captured peer %s:%d", h->peer_ip,remote_socket.sin_port );

//***********************************************************************************************
	//http_send_redirect(h, dest->str);
    //g_string_free( dest, 1 );
    //g_hash_free( args );
    //g_free( gw_addr );
    //g_free( redir );
}

void logout_peer( http_request *h, peer *p ) {
	
    remove_peer( p );
    http_send_redirect( h, CONF("LogoutURL") );
}

/*GHashTable* gpg_decrypt( char* ticket ) {
	
    int rfd[2], wfd[2], r;
    gchar *gpg, *msg;
    gchar **arg;
    GHashTable *data;
    pid_t pid;

    gpg = parse_template( CONF("DecryptCmd"), nocat_conf );
    arg = g_strsplit( gpg, " ", 0 );

    r = pipe(rfd);
    if (r) {
	g_error("Can't open read pipe to gpg: %m");
	return 0;
    }

    r = pipe(wfd);
    if (r) {
	g_error("Can't open write pipe to gpg: %m");
	return NULL;
    }

    pid = fork();
    if (pid == -1) {
	g_error( "Can't fork to exec gpg: %m" );
	return NULL;

    } else if (pid == 0) {
	dup2( wfd[0], STDIN_FILENO );
	close( wfd[1] );

	dup2( rfd[1], STDOUT_FILENO );
	close( rfd[0] );

	r = execv( *arg, arg );
	g_error( "execv %s (%s) failed: %m", gpg, *arg ); // Shouldn't happen.
	exit(-1);
    } 

    close( wfd[0] );
    close( rfd[1] );

    msg = g_new0(char, BUFSIZ);
    g_snprintf( msg, BUFSIZ,
	"-----BEGIN PGP MESSAGE-----\n\n"
	"%s\n"
	"-----END PGP MESSAGE-----",
	ticket );
    r = write( wfd[1], msg, strlen(msg) ); 
    if (r == -1){ g_error( "Can't write to gpg pipe: %m" );}
    close( wfd[1] );

    r = read( rfd[0], msg, BUFSIZ ); 
    g_assert( r > 0 );
    close( rfd[0] );
    msg[r] = '\0';

    waitpid( pid, &r, 0 );
    if (! WIFEXITED( r ))
	g_warning( "gpg returned error: %d (signal %d)", 
	    WEXITSTATUS(r), WIFSIGNALED(r) ? WTERMSIG(r) : 0 );

    data = parse_conf_string( msg );

    g_strfreev( arg );
    g_free( gpg );
    g_free( msg );

    return data;
}*/

/*int verify_peer( http_request *h, peer *p ) {
	
    GHashTable* msg;
    gchar *action, *mode, *dest;
    gchar *ticket = QUERY("ticket");
    GString *m;

    if (ticket == NULL) {
		g_warning("Invalid ticket from peer %s", p->ip);
		return 0;
    }

    msg = gpg_decrypt( QUERY("ticket") );
    m = g_hash_as_string(msg);
    g_message( "auth message: %s", m->str);

    // Check username if set
    // Check MAC
    // Check token

    // Set user
    // Set groups
    // Set token

    action = (gchar*) g_hash_table_lookup(msg, "Action");
    if (strcmp( action, "Permit" ) == 0) {
    	
		accept_peer( h );
    } else if (strcmp( action, "Deny" ) == 0) {
    	
		remove_peer( p );
    } else {
    	
		g_warning("Can't make sense of action %s!", action);
    }


    mode = (gchar*)g_hash_table_lookup(msg,"Mode");
    dest = (gchar*)g_hash_table_lookup(msg,"Redirect"); 
    if (strncmp(mode, "renew", 5) == 0) {
		http_send_header( h, 304, "No Response" );
    } else {
		http_send_redirect( h, dest );
    }

    g_hash_free( msg );
    return 1;
}*/

/*void handle_request( http_request* h ) {
	
    gchar* hostname = HEADER("Host");
    gchar* sockname = local_host(h);
    peer* p = find_peer(h->peer_ip);
    int r;

    g_assert(sockname != NULL);
    g_assert(hostname != NULL);

    if (hostname == NULL || strcmp( hostname, sockname ) != 0) {
    	
		capture_peer(h, p);
    }
    else if (strcmp( h->uri, "/logout" ) == 0) {
    	
		// logout
		logout_peer(h, p);
		// } else if (strcmp( h->uri, "/status" ) == 0) {
		// status
		// display_status(h, p);
    } 
    else {
    	
		// user with a ticket
		r = verify_peer(h, p);
		if (!r) capture_peer(h, p);
    }

    g_free(sockname);
}*/

void handle_request( http_request* h ) {
	
    gchar* hostname = HEADER("Host");
    gchar* sockname = local_host(h);
    
    gboolean is_new = FALSE;
    
    peer* p = find_peer(h->peer_ip, &is_new );
    
    /*if ((hostname == NULL) || (strcmp( hostname, sockname ) != 0)
    	 || is_new ) capture_peer(h,p);*/
    if ((hostname == NULL) || (strcmp( hostname, sockname ) != 0)) capture_peer(h,p);
        	 
   	//if (is_new) capture_peer(h,p);
    
    else if (strcmp( h->uri, "/logout" ) == 0) {
    	
		// logout
		logout_peer(h, p);
		// } else if (strcmp( h->uri, "/status" ) == 0) {
		// status
		// display_status(h, p);
    }
    g_free(sockname);
}

/*void initialize_driver (void) {
    return;
}*/
