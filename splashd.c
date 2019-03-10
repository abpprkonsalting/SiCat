# include <glib.h>
# include <stdio.h>
# include <netinet/in.h>
# include <sys/socket.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <signal.h>
# include <string.h>
# include <time.h>
# include <stdio.h>
# include <fcntl.h>
# include <unistd.h>
# include <syslog.h>
# include <libwebsockets.h>
# include "gateway.h"
# include "config.h"

#include <stdlib.h> 
#include <getopt.h> 
#include <stdarg.h>
//#include "websck.h"

//# include "splashd.h"


extern GHashTable *peer_tab;
//static int was_closed;
static int deny_deflate;
static int deny_mux;

enum demo_protocols {

	PROTOCOL_AUTHENTICATION,
	/* always last */
	DEMO_PROTOCOL_COUNT
};

static int 
callback_authentication(struct libwebsocket_context * this, struct libwebsocket *wsi, enum libwebsocket_callback_reasons reason, 
			void *user, void *in, size_t len) {

	// The 4096 number in the line bellow must be adjusted to the protocol I will design.
	unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + 4096 + LWS_SEND_BUFFER_POST_PADDING];
	int l;
 
	switch (reason) { 
		case LWS_CALLBACK_CLOSED: 
			//fprintf(stderr, "LWS_CALLBACK_CLOSED\n");
			g_message("LWS_CALLBACK_CLOSED"); 
			//was_closed = 1;
			
			/* It's suppose the websocket was closed, so depending on which way the websocket was
			closed I'm suppose to close and open it again?
			
			In any case I need to see what happens with call_libwebsocket_service*/
 
			break; 

		case LWS_CALLBACK_CLIENT_RECEIVE:

			/* Here is the real deal. I should receive here the command send by the server y pass it
			to some other place for analisys*/

			((char *)in)[len] = '\0';
			fprintf(stderr, "rx %d '%s'\n", (int)len, (char *)in);
			break;

		case LWS_CALLBACK_CLIENT_ESTABLISHED:

			/* This is the first time the wsck is stablished, so we should send something to the server.
			Is is a good time to call an initialization function that checks if this is the very first
			time we connect to the server (after bootup) to send the apropiate registration information.
			If not then well see what to do depending on the reason the wsck was stablished for.
		 	*/

			libwebsocket_callback_on_writable(this, wsi);
			break;

		case LWS_CALLBACK_CLIENT_WRITEABLE:

			/*We are here to send something. First we need to check if there is something to send to
			the server, in that case we will send it inmediatly with the code bellow, if not we simply
			exit. The buffer "my_buffer" in the sprintf instruction does not exist yet.

			For using this mecanism of writting to the server I will probably need a FIFO that will be
			filled asyncronusly by other parts of the program and that this function will check to see
			if there is something to send. Care should be taken with regard to accessing the FIFO when
			it is not completely full, so a kind of semaphore should be implemented.*/

			if (FIFO_HAS_CONTENT){
				l = sprintf((char *)&buf[LWS_SEND_BUFFER_PRE_PADDING],
						"%s;",(char*)my_buffer);

				libwebsocket_write(wsi,
		   		&buf[LWS_SEND_BUFFER_PRE_PADDING], l, LWS_WRITE_TEXT);

				/*
		 		* without at least this delay, we choke the browser
		 		* and the connection stalls, despite we now take care about
		 		* flow control
		 		*/
				
				/*I really need to see if this is important, because I don't want to waste 200 ms*/

				usleep(200);
			}

			/* get notified as soon as we can write again */

			libwebsocket_callback_on_writable(this, wsi);
			
			break;

		/*Here I must analyse what other "reasons" are important for my protocol in order to implement
		their handles.*/

		/* because we are protocols[0] ... */ 

		case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:
			if ((strcmp(in, "deflate-stream") == 0) && deny_deflate) {
				 fprintf(stderr, "denied deflate-stream extension\n"); 
				return 1;
			}
			if ((strcmp(in, "x-google-mux") == 0) && deny_mux) { 
				fprintf(stderr, "denied x-google-mux extension\n");
				return 1;
			} 
			break; 
		default: 
			break; 
	}

	return 0;
}

/* This definition should go to websck.h */ 
static struct libwebsocket_protocols protocols[] = { 
	{ 
		"authentication_protocol",
		callback_authentication,
		0, 

	}, 
	{ /* end of list */
		NULL, 
		NULL, 
		0 
	}
};

/*struct http_requests_count{
    gchar count;
    http_request** http_requests_array; 
} requests_count;

/*struct GIOChannelMine: public GIOChannel{

public:
	guint g_io_channel_get_flags_mine();

};

guint GIOChannelMine::g_io_channel_get_flags_mine(){

	return channel_flags;
}*/


gboolean show_socket_pairs(gchar* function_name, http_request *h){

	gint fd, r;
	struct sockaddr_in local_addr, remote_addr;
	int n = sizeof(struct sockaddr_in);
	gchar localaddr_ip[16], remoteaddr_ip[16];
	const gchar *r2;
	unsigned short int local_port, remote_port;

	fd = g_io_channel_unix_get_fd(h->sock);

	r = getsockname (fd, (struct sockaddr *)&local_addr,  &n );
	if (r == -1) g_error( "getsockname on socket_big failed: %m" );

	local_port = local_addr.sin_port;

	r2 = inet_ntop( AF_INET, &local_addr.sin_addr, localaddr_ip, INET_ADDRSTRLEN );
    	g_assert( r2 != NULL );

	n = sizeof(struct sockaddr_in);
	r = getpeername (fd, (struct sockaddr *)&remote_addr,  &n );
	if (r == -1) g_error( "getsockname on socket_small failed: %m" );

	remote_port = remote_addr.sin_port;

	r2 = inet_ntop( AF_INET, &remote_addr.sin_addr, remoteaddr_ip, INET_ADDRSTRLEN );
    	g_assert( r2 != NULL );

	g_message( "%s : fd = %d --- remote address = %s:%d --- local address = %s:%d",
			function_name , fd, remoteaddr_ip, remote_port, localaddr_ip, local_port);

	return TRUE;

}

gboolean call_libwebsocket_service( struct libwebsocket_context* context){
	
	int n = libwebsocket_service(context,0);
        return TRUE;
}


/************ Check peer timeouts **************/

gboolean check_peers( void *dummy ) {

	time_t now = time(NULL);
	//g_message("Checking peers for expiration");
	g_hash_table_foreach_remove( peer_tab, (GHRFunc)check_peer_expire, &now );
	return TRUE;
}

/************* Connection handlers ************/

/************* HangUp Connection handle *******
gboolean handle_broken (GIOChannel *sock,gint priority ,GIOCondition cond, http_request *h){

	g_message( "entering handle_broken with h = %d",h);
	//GIOChannelError* Cerror = g_new0(GIOChannelError, 1);	
	//g_io_channel_shutdown(h->sock,FALSE,Cerror);
	//g_free(Cerror);
	g_io_channel_close( h->sock );
	g_io_channel_unref( h->sock );	
	http_request_free(h);
	h = NULL;
	g_message( "leaving handle_broken with h = %d",h);
	return TRUE;

}*/

/************* Read Input Data Connection handle *******/
gboolean handle_read( GIOChannel *sock, GIOCondition cond, http_request *h ) {

	gint res;
	GIOCondition* channel_status;
	
	//g_debug( "entering handle_read" );
	//g_message( "entering handle_read with h = %d",h);

	if (h != NULL){

		//show_socket_pairs("handle_read", h);
		//channel_status = g_io_channel_get_buffer_condition(h->sock);

		if (http_request_read( h ) != 0){

			if (! http_request_ok(h)) return TRUE;
			handle_request(h);/**/
		}

		/*int n;
		for (n = 0; n < requests_count.count; n++){
			res = g_strcasecmp(requests_count.http_requests_array[n]->peer_ip, h->peer_ip);

			if ((res == 0) && (requests_count.http_requests_array[n] != h)){

				g_io_channel_close( requests_count.http_requests_array[n]->sock );
				g_io_channel_unref( requests_count.http_requests_array[n]->sock );
				http_request_free( requests_count.http_requests_array[n] );
			
				http_request** j = requests_count.http_requests_array;
				requests_count.count--;
				requests_count.http_requests_array = g_new0(http_request *, requests_count.count);

				int k,l;
				for (k = 0; k < n; k++){

					requests_count.http_requests_array[k] = j[k];

				}
				for (l = n; l <requests_count.count;l++){

					requests_count.http_requests_array[l] = j[l+1];
				}
				g_free(j);
			}
		}*/
	
		g_io_channel_close( h->sock );
		////Cerror = g_new0(GIOChannelError, 1);	
		////g_io_channel_shutdown(h->sock,FALSE,Cerror);

		g_io_channel_unref( h->sock );


		http_request_free( h );
		////h = NULL;
	}

	//g_debug( "exiting handle_read" );
	//g_message( "exiting handle_read");
	return FALSE;
}


/************* Accept Connection handle *******/
//gboolean handle_accept( GIOChannel *sock, GIOCondition cond, struct http_requests_count* requests_ptr ) {
gboolean handle_accept( GIOChannel *sock, GIOCondition cond,  void *dummy ) {

	GIOChannel *conn;
	http_request *req; /* defined in http.h */
	int fd;

	//g_message("entrÃ© en handle_accept");

	fd = accept( g_io_channel_unix_get_fd(sock), NULL, NULL );

	/* The line below need to be substituted by other error checking method that don't break daemon execution*/
	g_assert( fd != -1 );
	
	conn = g_io_channel_unix_new( fd );
	req  = http_request_new( conn );

	//show_socket_pairs("handle_accept", req);	
	
	/*
	g_message( "requests_ptr->count = %d",requests_ptr->count);

	if (requests_ptr->count == 0){

		
		requests_ptr->http_requests_array = g_new0(http_request *, 1);
		requests_ptr->http_requests_array[0] = req;
		g_message( "m = 0 -- req->peer_ip: %s", requests_ptr->http_requests_array[0]->peer_ip);
		requests_ptr->count++;
	}
	else{
		int m;
		for (m = 0; m < requests_ptr->count; m++){

			//gint res = g_strcasecmp(((http_request*)(requests_ptr->http_requests_array) + (http_request*)n)->peer_ip,
			//             	req->peer_ip);
			g_message("m = %d -- req->peer_ip: %s",m,requests_ptr->http_requests_array[m]->peer_ip);
		}
		requests_ptr->count++;
		requests_ptr->http_requests_array = g_renew(http_request*, requests_ptr->http_requests_array, requests_ptr->count);
		requests_ptr->http_requests_array[requests_ptr->count-1] = req;
		
	}
	*/
	g_io_add_watch( conn, G_IO_IN, (GIOFunc) handle_read, req );

	//g_io_add_watch( conn, G_IO_HUP, (GIOFunc) handle_broken, req );
	//g_io_add_watch_full(conn,G_PRIORITY_HIGH,G_IO_HUP,(GIOFunc) handle_broken,req,NULL);

	//g_message("salÃ­ de handle_accept");
	return TRUE;
}


/************* main ************/

static int exit_signal = 0;
static FILE *pid_file  = NULL;

gboolean check_exit_signal ( GMainLoop *loop ) {
    if (exit_signal) {
	g_message( "Caught exit signal %d!", exit_signal );
	if (pid_file != NULL) {
	    unlink( NC_PID_FILE );
	    fclose( pid_file );
	}
	g_main_quit( loop );
    }
    return TRUE;
}

void signal_handler( int sig ) {
    switch(sig) {
	case SIGINT:
	    /*log_message(LOG_FILE,"interrupt signal caught");*/
	    exit_signal = sig;
	    break;
	case SIGTERM:
	    /*log_message(LOG_FILE,"terminate signal caught");*/
	    exit_signal = sig;
	    break;
	case SIGHUP:
	    /*log_message(LOG_FILE,"hangup signal caught");*/
	    break;
    }
}

void daemonize(void) {
	int f;
	pid_t r, sid;

	//g_message( "EntrÃ© en daemonize");
	if (getppid() == 1) return; /* already a daemon */

	r = fork();
	//g_message( "despuÃ©s del fork %d",r);
	if (r<0) 
	{
		g_message( "fork error");
		exit(1); /* fork error */
	}
	if (r>0)	//This is the return of fork for the parent process, the pid of the child
	{ 
		exit(0); /* parent exits */
	}
	//g_message( "We are the child %d",r);

	/* child (daemon) continues */
	sid = setsid(); /* obtain a new process group */
	//g_message("despuÃ©s del sid");
	if (sid < 0)
	{
		//g_message("setsid error");
		exit(1);
	}

	for (f = getdtablesize(); f >= 0; --f)
	{
		//g_message( "f: %d",f);
		close(f); /* close all descriptors */
	}
	//g_message( "cerrados los descriptores");
	f = open("/dev/null",O_RDWR); dup(f); dup(f); /* handle standard I/O */
	if (f < 0)
	{
		//g_message("error opening file");
		exit(1);
	}
	umask(027); /* set newly created file permissions */
    
	//g_message(NC_STATE_DIR);

	/*chdir( NC_STATE_DIR );  change running directory, Esta lÃ­nea estÃ¡ comentada temporalmente para substituirla
				por la de abajo*/
	chdir("/var");

	//g_message( "cambiado el running directory");

	//g_message(NC_PID_FILE);

	/*pid_file = fopen( NC_PID_FILE, "w" ); Esta lÃ­nea estÃ¡ comentada temporalmente para substituirla po la de abajo*/

	pid_file = fopen( "/var/run/splashd.pid", "w" );

	if (pid_file == NULL)
	{
		//g_message( "No se pudo abrir el pid_file");
		exit(1); /* can not open */
	}
	if (lockf( fileno(pid_file), F_TLOCK, 0 ) < 0) 
	{
        	//g_message( "No se pudo lock el pid_file");
		exit(0); /* can not lock */
	}

	/* write PID to lockfile */
	//fprintf(pid_file, "%d\n", getpid());
   	if (fprintf(pid_file, "%d\n", getpid()) < 0)
	{
		//g_message( "error en el fprintf()");
		exit(0);
	}
	//g_message( "pasÃ© el fprintf");
	// fclose(lfp);

	// signal(SIGCHLD,SIG_IGN); /* ignore child */
	signal(SIGTSTP,SIG_IGN); /* ignore tty signals */
	signal(SIGTTOU,SIG_IGN);
	signal(SIGTTIN,SIG_IGN);
	signal(SIGHUP,  signal_handler); /* catch hangup signal */
	signal(SIGTERM, signal_handler); /* catch kill signal */
	signal(SIGINT,  signal_handler);
	//g_message( "salÃ­ de daemonize");
}

void g_syslog (const gchar *log_domain, GLogLevelFlags log_level, 
	       const gchar *message, gpointer user_data) {

    int priority;

    switch (log_level & G_LOG_LEVEL_MASK) {
	case G_LOG_LEVEL_ERROR:	    priority = LOG_ERR;	    break;
	case G_LOG_LEVEL_CRITICAL:  priority = LOG_CRIT;    break;
	case G_LOG_LEVEL_WARNING:   priority = LOG_WARNING; break;
	case G_LOG_LEVEL_MESSAGE:   priority = LOG_NOTICE;  break;
	case G_LOG_LEVEL_INFO:	    priority = LOG_INFO;    break;
	case G_LOG_LEVEL_DEBUG:	    
	default:		    priority = LOG_DEBUG;   break;
				
    }

    syslog( priority | LOG_DAEMON, message );

    if (log_level & G_LOG_FLAG_FATAL)
	exit_signal = -1;
}

void initialize_log (void) 
{
	/* L'ineas removidas temporalmente para poder debugear desde el principio*/

	if (strncmp( CONF("LogFacility"), "syslog", 6 ) == 0)
	{
		openlog( CONF("SyslogIdent"), LOG_CONS | LOG_PID, LOG_DAEMON );	
		g_log_set_handler( NULL,G_LOG_LEVEL_MASK | G_LOG_FLAG_RECURSION | G_LOG_FLAG_FATAL,g_syslog, NULL );
	}
	

	/* L'ineas agregadas temporalmente para poder debugear desde el principio

	openlog( "splashd: ", LOG_CONS | LOG_PID, LOG_DAEMON );
	g_log_set_handler( NULL,G_LOG_LEVEL_MASK | G_LOG_FLAG_RECURSION | G_LOG_FLAG_FATAL,g_syslog, NULL );
	*/
}

int main (int argc, char **argv) {

	GMainLoop  *loop;
	GIOChannel *sock;

/**************************************Variables para el websocket****************************************************/

	/*The following variables must take their working values from the configuration file: NoCat.conf,
	  otherwise the program exits*/

	char* wsk_server_address = NULL;
	int wsk_server_port = 0;

        /*The following variables are internal to the program*/

	struct libwebsocket_context* context;
	struct lws_context_creation_info* context_creation_info;
	struct libwebsocket *wsi_dumb;

/**********************************************************************************************************************/

	/* read nocat.conf */

	nocat_conf = read_conf_file( NC_CONF_PATH "/nocat.conf" );

	//printf("Se cargÃ³ el config\n");

	if (argc < 2 || strncmp(argv[1], "-D", 2) != 0) daemonize();

	/* initalize the log */

	initialize_log();

	/* set network parameters */
	set_network_defaults( nocat_conf );

	/* initialize the gateway type driver */
	initialize_driver();

	/* initialize the firewall */
	fw_init( nocat_conf );

	/* initialize the peer table */
	peer_tab = g_hash_new();

	/* initialize the listen socket */
	sock = http_bind_socket( CONF("GatewayAddr"), CONFd("GatewayPort"), CONFd("ListenQueue") );

	/* initialize the http_requests_array */
	//g_message( "here");
	//http_requests_ptr->count = 0;
	//requests_count.count = 0;
	//g_message( "or here");

/************************************************************************************************************/
	/* create and initialize the websocket connection */

	wsk_server_address = CONF("wsk_server_address");
	if (wsk_server_address == NULL){

		g_message("The websocket server address parameter can't be NULL");
		return -1;

	}
	wsk_server_port = CONFd("wsk_server_port");
	if (wsk_server_port < 1){

		g_message("The websocket server port parameter can't less than 1");
		return -1;

	}

	//g_try_new0(struct_type, n_structs); Esto es lo que debo usar en la versión final pues la versión de abajo
						//aborta el programa en un error
	context_creation_info = g_new0(struct lws_context_creation_info, 1);

	context_creation_info->port = CONTEXT_PORT_NO_LISTEN;
	context_creation_info->iface = CONF("wsk_iface");
	context_creation_info->protocols = &protocols;
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

	context = libwebsocket_create_context(context_creation_info);

	// Aquí debo chequear por error en la creación del context y tomar una determinación de que hacer si no se pudo crear.
	// return -1; ?
	
	/* create a client websocket */

	//wsi_dumb = libwebsocket_client_connect(context, wsk_server_address, wsk_server_port, CONFd("wsk_use_ssl"), CONF("wsk_path_on_server"),
	//			CONF("wsk_server_hostname"), CONF("wsk_origin_name"), protocols[CONFd("wsk_protocol")].name, CONFd("ietf_version"));


	//Revisar las variables wsk_server_hostname y wsk_origin_name de la línea de arriba para poder parametrizar la llamada a libwebsocket_client_connect
	wsi_dumb = libwebsocket_client_connect(context, wsk_server_address, wsk_server_port, CONFd("wsk_use_ssl"), CONF("wsk_path_on_server"),
				"","", protocols[CONFd("wsk_protocol")].name, CONFd("ietf_version")); 
	if (wsi_dumb == NULL) {
		g_message("libwebsocket connect failed");
		return -1;
	}

/************************************************************************************************************/

	/* initialize the main loop and handlers */
	loop = g_main_new(FALSE);//

	//g_io_add_watch( sock, G_IO_IN, (GIOFunc) handle_accept, &requests_count );
	g_io_add_watch( sock, G_IO_IN, (GIOFunc) handle_accept,NULL);
	g_timeout_add( 30000, (GSourceFunc) check_peers, NULL );
	g_timeout_add( 1000, (GSourceFunc) check_exit_signal, loop );
	g_timeout_add( 100, (GSourceFunc) call_libwebsocket_service, context );
    
	/* Go! */
	g_message("starting main loop");
	g_main_run( loop );
	g_message("exiting main loop");
	return 0;
}
