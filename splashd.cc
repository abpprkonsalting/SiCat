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
	if (r == -1) g_error( "getsockname on socket_big failed: %m" );

	local_port = local_addr.sin_port;

	r2 = (gchar*)inet_ntop( AF_INET, &local_addr.sin_addr, localaddr_ip, INET_ADDRSTRLEN );
    	g_assert( r2 != NULL );

	n = sizeof(struct sockaddr_in);
	r = getpeername (fd, (struct sockaddr *)&remote_addr,  &n );
	if (r == -1) g_error( "getsockname on socket_small failed: %m" );

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

	gboolean result = FALSE;
	
	if (h != NULL){

		if (http_request_read(h) != 0){

			if (!http_request_ok(h)) result = TRUE;
			else handle_request(h);
		}

		g_io_channel_close( h->sock );
		g_io_channel_unref( h->sock );
		http_request_free( h );
	}

	return result;
}

/************* Accept Connection handle *******/
gboolean handle_accept( GIOChannel* sock, GIOCondition cond,  void* dummy ) {

	GIOChannel* conn;
	http_request* req; /* defined in http.h */
	int fd;

	fd = accept( g_io_channel_unix_get_fd(sock), NULL, NULL );

	/* The line below need to be substituted by other error checking method that don't break daemon execution*/
	g_assert( fd != -1 );
	
	conn = g_io_channel_unix_new( fd );
	req  = http_request_new( conn );

	//show_socket_pairs("handle_accept", req);	
	
	g_io_add_watch( conn, G_IO_IN, (GIOFunc) handle_read, req );

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

	/*chdir( NC_STATE_DIR );	change running directory, Esta lí­nea está comentada temporalmente para substituirla
								por la de abajo*/
	chdir("/var");

	/*pid_file = fopen( NC_PID_FILE, "w" ); Esta lí­nea está comentada temporalmente para substituirla po la de abajo*/

	pid_file = fopen( "/var/run/splashd.pid", "w" );

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
		g_log_set_handler( 0,(GLogLevelFlags)(G_LOG_LEVEL_MASK | G_LOG_FLAG_RECURSION | G_LOG_FLAG_FATAL),g_syslog,0);
	}
}

/************* main ************/

int main(int argc, char** argv)
{
	GMainLoop  *loop;
	GIOChannel *sock;

	/* read nocat.conf */

	nocat_conf = read_conf_file( NC_CONF_PATH "/nocat.conf" );
	
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
	
	wsk_comm_interface = NULL;
	wsk_comm_interface = new class comm_interface();
	if (wsk_comm_interface == NULL){
		
		g_message("websocket initialization error, aborting program...");
		return -1;
	}

	/* initialize the main loop and handlers */
	loop = g_main_new(FALSE);//

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
