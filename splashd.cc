#include "splashd.h"

gboolean show_socket_pairs(gchar* function_name, http_request *h){

	gint fd, r;
	struct sockaddr_in local_addr, remote_addr;
	unsigned int n = sizeof(struct sockaddr_in);
	gchar localaddr_ip[16], remoteaddr_ip[16];
	const gchar *r2;
	unsigned short int local_port, remote_port;

	fd = g_io_channel_unix_get_fd(h->sock);

	r = getsockname (fd, (struct sockaddr *)&local_addr,  &n );
	if (r == -1) { g_error( "getsockname on socket_big failed: %m" ); }

	local_port = local_addr.sin_port;

	r2 = (gchar*)inet_ntop( AF_INET, &local_addr.sin_addr, localaddr_ip, INET_ADDRSTRLEN );
    	g_assert( r2 != NULL );

	n = sizeof(struct sockaddr_in);
	r = getpeername (fd, (struct sockaddr *)&remote_addr,  &n );
	if (r == -1) { g_error( "getsockname on socket_small failed: %m" );}

	remote_port = remote_addr.sin_port;

	r2 = (gchar*)inet_ntop( AF_INET, &remote_addr.sin_addr, remoteaddr_ip, INET_ADDRSTRLEN );
    	g_assert( r2 != NULL );

	g_message( "%s : fd = %d --- remote address = %s:%d --- local address = %s:%d",
			function_name , fd, remoteaddr_ip, remote_port, localaddr_ip, local_port);

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

	//peer* p; 
	
	if (!(h->is_used)){
		
		//show_socket_pairs((char*)"entering http_request_read with", h);
    	
			if (http_request_read(h) != 0){

				if (!http_request_ok(h)) {
					
					//g_message("shutdown fd = %d",g_io_channel_unix_get_fd (h->sock));
					g_io_channel_set_close_on_unref(h->sock,TRUE);
					g_io_channel_shutdown(h->sock,FALSE,NULL);
					g_io_channel_unref( h->sock );
					requests->remove(h);
					return FALSE;
				}
				else {
					h->is_used = TRUE;
					handle_request(h);
					return FALSE;
				}
			}
		
		//g_message("shutdown fd = %d",g_io_channel_unix_get_fd (h->sock));
		g_io_channel_set_close_on_unref(h->sock,TRUE);
		g_io_channel_shutdown(h->sock,FALSE,NULL);
		g_io_channel_unref( h->sock );
		requests->remove(h);
	}

	return FALSE;
}

/************* Accept Connection handle *******/
gboolean handle_accept( GIOChannel* sock, GIOCondition cond,  void* dummy ) {

	GIOChannel* conn;
	http_request* req; /* defined in http.h */
	int fd,r,n;
	pid_t mypid;
	GError* gerror = NULL;

	fd = accept( g_io_channel_unix_get_fd(sock), NULL, NULL );

	/* The line below need to be substituted by other error checking method that don't break daemon execution*/
	g_assert( fd != -1 );
	
	n = fcntl( fd, F_GETFL, 0 );
    //if (n == -1) g_error("fcntl F_GETFL on %s: %m", ip );
    //g_message("n = %d",n);
    
    //g_message("O_NONBLOCK modified = %d",n & O_NONBLOCK);
    
    r = fcntl( fd, F_SETFL, n | O_NONBLOCK);

	//if (r == -1) g_error("fcntl F_SETFL O_NDELAY on %s: %m", ip );
	
	//n = fcntl( fd, F_GETFL, 0 );
    //if (n == -1) g_error("fcntl F_GETFL on %s: %m", ip );
    //g_message("n again = %d",n);
    //g_message("O_NONBLOCK modified again = %d",n & O_NONBLOCK);
    
    mypid = getpid();
    r = fcntl( fd, F_SETOWN, mypid);

	
	conn = g_io_channel_unix_new( fd );
	
	g_io_channel_set_encoding(conn,NULL,&gerror);
	if (gerror != NULL) g_message(gerror->message);
	
	//req  = http_request_new( conn );
	req = requests->add(conn);

	//show_socket_pairs((char*)"handle_accept", req);	
	
	g_io_add_watch( conn, G_IO_IN, (GIOFunc) handle_read, req );
	
	//g_message("added watch for request %d",requests->get_index(req));

	//g_io_add_watch( conn, G_IO_HUP, (GIOFunc) handle_broken, req );
	//g_io_add_watch_full(conn,G_PRIORITY_HIGH,G_IO_HUP,(GIOFunc) handle_broken,req,NULL);

	return TRUE;
}

gboolean check_exit_signal ( GMainLoop *loop ) {
	
	/*if (wsk_wants_close){
		if (wsk_comm_interface->wsi_dumb == NULL) g_message("wsi = NULL en check_exit_signal");
		else {
			g_message("wsi_exit = %d", (unsigned int)wsk_comm_interface->wsi_dumb);
			//wsk_wants_close = false;
		}
	}*/
	
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
	case SIGURG:
		g_message("out of band data arrived");
		break;
    }
}

void daemonize(void) {
	int f;
	pid_t r, sid;

	if (getppid() == 1) return; /* already a daemon */

	r = fork();
	if (r<0) 
	{
		g_message( "fork error");
		exit(1); /* fork error */
	}
	if (r>0)	//This is the return of fork for the parent process, the pid of the child
	{ 
		exit(0); /* parent exits */
	}

	/* child (daemon) continues */
	
	sid = setsid(); /* obtain a new process group */

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

	f = open("/dev/null",O_RDWR); dup(f); dup(f); /* handle standard I/O */
	if (f < 0)
	{
		//g_message("error opening file");
		exit(1);
	}
	umask(027); /* set newly created file permissions */

	chdir( NC_STATE_DIR );
	
	//chdir("/var");

	pid_file = fopen( NC_PID_FILE, "w" );

	//pid_file = fopen( "/var/run/splashd.pid", "w" );

	if (pid_file == NULL)
	{
		exit(1); /* can not open */
	}
	if (lockf( fileno(pid_file), F_TLOCK, 0 ) < 0) 
	{
		exit(0); /* can not lock */
	}

	/* write PID to lockfile */

   	if (fprintf(pid_file, "%d\n", getpid()) < 0)
	{
		//g_message( "error en el fprintf()");
		exit(0);
	}

	// fclose(lfp);

	// signal(SIGCHLD,SIG_IGN); /* ignore child */
	signal(SIGTSTP,SIG_IGN); /* ignore tty signals */
	signal(SIGTTOU,SIG_IGN);
	signal(SIGTTIN,SIG_IGN);
	signal(SIGHUP,  signal_handler); /* catch hangup signal */
	signal(SIGTERM, signal_handler); /* catch kill signal */
	signal(SIGINT,  signal_handler);
	signal(SIGURG,  signal_handler);
}

void g_syslog (const gchar* log_domain, GLogLevelFlags log_level, 
	       const gchar* message, gpointer user_data) {

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
	if (strncmp( CONF("LogFacility"), "syslog", 6 ) == 0)
	{
		openlog(CONF("SyslogIdent"), LOG_CONS | LOG_PID, LOG_DAEMON );	
		g_log_set_handler( 0,(GLogLevelFlags)(G_LOG_LEVEL_MASK | G_LOG_FLAG_RECURSION | G_LOG_FLAG_FATAL
			| G_LOG_LEVEL_DEBUG | G_LOG_LEVEL_INFO),g_syslog,0);
	}
}

/************* main ************/

int main(int argc, char** argv)
{
	GMainLoop  *loop;
	GIOChannel *sock;

	/* read sicat.conf */

	nocat_conf = read_conf_file( NC_CONF_PATH "/sicat.conf" );
	
	if (argc < 2 || strncmp(argv[1], "-D", 2) != 0) daemonize();

	/* initalize the log */

	initialize_log();
	
	/* set network parameters */
	set_network_defaults( nocat_conf );

	/* initialize the gateway type driver
	initialize_driver();*/

	/* initialize the firewall */
	fw_init(nocat_conf);

	/* initialize the peer table */
	peer_tab = g_hash_new();

	/* initialize the listen socket */
	sock = http_bind_socket( CONF("GatewayAddr"), CONFd("GatewayPort"), CONFd("ListenQueue") );

	/* create and initialize the websocket comunication interface */
	
	/*bool otra;
	char men[1024];
	
	strcpy(men,"<Protocol Version=\"3\">\
	<Frame Type=\"1\" Command=\"6\" FrameCount=\"1\" AckCount=\"0\" BodyFrameSize=\"0\" FromDeviceId=\"\" ToDeviceId=\"621d40c9-3731-4d4e-8751-690e3e4167e6\">\
		<Parameters Count=\"2\">\
			<Parameter Name=\"IsAuthenticated\" Value=\"true\" />\
			<Parameter Name=\"UserToken\" Value=\"48e3f2d3-f805-4ea7-afda-d0fe2344b0b3\" />\
		</Parameters>\
	</Frame>\
</Protocol>");
	
	class m_frame* mi_trama = new class m_frame(men,0,&otra);
	
	g_message("Version: %d",mi_trama->Version);
	g_message("Type: %d",mi_trama->Type);
	g_message("Command: %d",mi_trama->Command);
	g_message("FrameCount: %d",mi_trama->FrameCount);
	g_message("AckCount: %d",mi_trama->AckCount);
	g_message("BodyFrameSize: %d",mi_trama->BodyFrameSize);
	
	g_message("Parametro 1 -- Nombre: %s , Valor: %s ",mi_trama->parameters->items[0]->nombre,mi_trama->parameters->items[0]->valor);
	g_message("Parametro 2 -- Nombre: %s , Valor: %s ",mi_trama->parameters->items[1]->nombre,mi_trama->parameters->items[1]->valor);
	
	return 0;*/
	
	macAddressFrom = get_mac_address (CONF("ExternalDevice"));
	
	wsk_comm_interface = NULL;
	wsk_comm_interface = new class comm_interface();
	if (wsk_comm_interface == NULL){
		
		g_message("websocket initialization error, aborting program...");
		return -1;
	}
	
	requests = g_new0(h_requests,1);

	/* initialize the main loop and handlers */
	loop = g_main_loop_new(NULL,FALSE);//

	//g_io_add_watch( sock, G_IO_IN, (GIOFunc) handle_accept, &requests_count );
	g_io_add_watch( sock, G_IO_IN, (GIOFunc) handle_accept,NULL);
	g_timeout_add( 30000, (GSourceFunc) check_peers, NULL );
	g_timeout_add( 1000, (GSourceFunc) check_exit_signal, loop );
    
	/* Go! */
	g_message("starting main loop");
	g_main_run( loop );
	g_message("exiting main loop");
	
	return 0;
}
