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
	if (r == -1) { g_debug( "%s: getsockname failed: %m",function_name ); }

	local_port = local_addr.sin_port;

	r2 = (gchar*)inet_ntop( AF_INET, &local_addr.sin_addr, localaddr_ip, INET_ADDRSTRLEN );
    	//g_assert( r2 != NULL );

	n = sizeof(struct sockaddr_in);
	r = getpeername (fd, (struct sockaddr *)&remote_addr,  &n );
	if (r == -1) { g_debug( "%s: getpeername failed: %m",function_name );}

	remote_port = remote_addr.sin_port;

	r2 = (gchar*)inet_ntop( AF_INET, &remote_addr.sin_addr, remoteaddr_ip, INET_ADDRSTRLEN );
    	//g_assert( r2 != NULL );

	g_debug( "%s: fd = %d -- remote address = %s:%d -- local address = %s:%d",
			function_name , fd, remoteaddr_ip, remote_port, localaddr_ip, local_port);

	return TRUE;

}

/************ Check peer timeouts **************/

gboolean check_peers( void *dummy ) {

	time_t now = time(NULL);
	g_hash_table_foreach_remove( peer_tab, (GHRFunc)check_peer_expire, &now );
	return TRUE;
}

/************* Connection handlers ************/

/************* Read Input Data Connection handle *******/
gboolean handle_read( GIOChannel *sock, GIOCondition cond, http_request *h ) {
	
	g_debug("handle_read: reading request fd = %d",g_io_channel_unix_get_fd (h->sock));
	//g_debug("source_id after = %d",h->source_id);
	guint r;
	
	r= http_request_read(h);
	
	if (r == 1){

		http_request_ok(h);
			
		if (handle_request(h) == 0) {
			
			g_debug("handle_read: leaving without shutting down request fd = %d",g_io_channel_unix_get_fd (h->sock));
			return FALSE;
		}
	
	}
	else if (r == 0) {
		
		g_debug("handle_read: leaving without shutting down request fd = %d",g_io_channel_unix_get_fd (h->sock));
		return TRUE;
	}
	
	g_debug("handle_read: shutting down request fd = %d",g_io_channel_unix_get_fd (h->sock));

	g_io_channel_shutdown(h->sock,TRUE,NULL);
	g_io_channel_unref( h->sock );
	http_request_free (h);

	return FALSE;
}

/************* Accept Connection handle *******/
gboolean handle_accept( GIOChannel* sock, GIOCondition cond,  void* dummy ) {

	GIOChannel* conn;
	http_request* req; /* defined in http.h */
	GError* gerror = NULL;
	int fd,r,n;
	pid_t mypid;
	guint sourc_id;
	

	g_debug ("handle_accept: entering..");
	fd = accept( g_io_channel_unix_get_fd(sock), NULL, NULL );

	n = fcntl( fd, F_GETFL, 0 );
    r = fcntl( fd, F_SETFL, n | O_NONBLOCK);
    
    mypid = getpid();
    r = fcntl( fd, F_SETOWN, mypid);
	
	conn = g_io_channel_unix_new( fd );
	
	//g_io_channel_set_encoding(conn,NULL,&gerror);
	
	g_io_channel_set_close_on_unref(conn,TRUE);
	g_io_channel_set_buffer_size(conn,4096);
	
	req  = http_request_new( conn, fd );
	
	if (req != NULL){
		
		show_socket_pairs((char*)"handle_accept", req);
		sourc_id = g_io_add_watch(conn, G_IO_IN,(GIOFunc)handle_read, req);
		//g_debug("source_id before= %d",sourc_id);
		req->source_id = sourc_id;
	}
	else {
		
		g_io_channel_shutdown(conn,FALSE,NULL);
		g_io_channel_unref(conn);
		
	}
	g_debug ("handle_accept: leaving..");
	return TRUE;
}

gboolean handle_accept6( GIOChannel* sock, GIOCondition cond,  void* dummy ) {

	GIOChannel* conn;
	http_request* req; /* defined in http.h */
	int fd,r,n;
	pid_t mypid;
	GError* gerror = NULL;

	fd = accept( g_io_channel_unix_get_fd(sock), NULL, NULL );

	/* The line below need to be substituted by other error checking method that don't break daemon execution*/
	//g_assert( fd != -1 );
	
	n = fcntl( fd, F_GETFL, 0 );
    //if (n == -1) g_error("fcntl F_GETFL on %s: %m", ip );
    //g_message("n = %d",n);
    
    //g_message("O_NONBLOCK modified = %d",n & O_NONBLOCK);
    
    r = fcntl( fd, F_SETFL, n | O_NONBLOCK);

	//if (r == -1) g_error("fcntl F_SETFL O_NDELAY on %s: %m", ip );
    
    mypid = getpid();
    r = fcntl( fd, F_SETOWN, mypid);
	
	conn = g_io_channel_unix_new( fd );
	
	//g_io_channel_set_encoding(conn,NULL,&gerror);
	//if (gerror != NULL) g_message(gerror->message);
	
	g_io_channel_set_close_on_unref(conn,TRUE);
	
	req  = http_request_new6( conn, fd );
	//req = requests->add6(conn);

	//show_socket_pairs((char*)"handle_accept", req);	
	
	if (req != NULL) g_io_add_watch( conn, G_IO_IN, (GIOFunc) handle_read, req );
	else {
		
		g_io_channel_shutdown(conn,FALSE,NULL);
		g_io_channel_unref( conn );
		return FALSE;
		
	}
	return TRUE;
}


gboolean check_exit_signal ( GMainLoop *loop ) {
	
    //printf("checking exit signal..");
    if (exit_signal) {
	g_message( "check_exit_signal: Caught exit signal %d!", exit_signal );
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
		g_message("signal_handler: out of band data arrived");
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
		g_message( "daemonize: fork error");
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
    size_t message_len = 0;
    div_t result;
    unsigned int t = 1;
	gchar* message_part = NULL;
	unsigned int width = (unsigned int) CONFd("llwidth");
	unsigned int mem = (unsigned int) CONFd("lmem");
	
	pid_t my_pid;
	gchar* nombre;
	gchar* contenido;
	gsize length;
	gchar *start_memory, *end_memory;
	gchar *VmSize, *VmRSS, *VmData, *VmStk, *VmLib;
	unsigned int memory_size;

    switch (log_level & G_LOG_LEVEL_MASK) {
		case G_LOG_LEVEL_ERROR:	    priority = LOG_ERR;	    break;
		case G_LOG_LEVEL_CRITICAL:  priority = LOG_CRIT;    break;
		case G_LOG_LEVEL_WARNING:   priority = LOG_WARNING; break;
		case G_LOG_LEVEL_MESSAGE:   priority = LOG_NOTICE;  break;
		case G_LOG_LEVEL_INFO:	    priority = LOG_INFO;    break;
		case G_LOG_LEVEL_DEBUG:	    
		default:		    		priority = LOG_DEBUG;   break;
				
    }
	message_len = strlen(message);
	
	if (mem){
	
		my_pid = getpid();
		nombre = g_new0(gchar,100);
		g_sprintf(nombre,"%s%d%s","/proc/",my_pid,"/status");
		g_file_get_contents(nombre,&contenido,&length,NULL);
		g_free(nombre);
		
		start_memory = g_strstr_len(contenido,-1,"VmSize:");
		end_memory = g_strstr_len(contenido,-1,"VmLck:");
		memory_size = end_memory - start_memory - 9;
		VmSize = g_strndup(start_memory+8,memory_size);
		g_strchug(VmSize);
		
		start_memory = g_strstr_len(contenido,-1,"VmRSS:");
		end_memory = g_strstr_len(contenido,-1,"VmData:");
		memory_size = end_memory - start_memory - 8;
		VmRSS = g_strndup(start_memory+7,memory_size);
		g_strchug(VmRSS);
		
		start_memory = g_strstr_len(contenido,-1,"VmData:");
		end_memory = g_strstr_len(contenido,-1,"VmStk:");
		memory_size = end_memory - start_memory - 9;
		VmData = g_strndup(start_memory+8,memory_size);
		g_strchug(VmData);
		
		start_memory = g_strstr_len(contenido,-1,"VmStk:");
		end_memory = g_strstr_len(contenido,-1,"VmExe:");
		memory_size = end_memory - start_memory - 8;
		VmStk = g_strndup(start_memory+7,memory_size);
		g_strchug(VmStk);
		
		start_memory = g_strstr_len(contenido,-1,"VmLib:");
		end_memory = g_strstr_len(contenido,-1,"VmPTE:");
		memory_size = end_memory - start_memory - 8;
		VmLib = g_strndup(start_memory+7,memory_size);
		g_strchug(VmLib);
		
		g_free(contenido);
	}
		
	if ( message_len > width ) {
		
		result = div(message_len,width);
		t = result.quot;
		if (result.rem > 0) t = t + 1;
	}
	
	for (unsigned int i = 0; i < t; i++){
		
		message_part = g_new0(gchar,width + 2 + 50);
		
		strncpy (message_part,message+(i*width),width);
		
		if (mem){
			if ( i == 0) syslog( priority | LOG_DAEMON, "%s - %s - %s - %s - %s -- %s",VmSize,VmRSS,VmData,VmStk,VmLib,message_part);
			else syslog( priority | LOG_DAEMON, "%s", message_part);
		}
		else syslog( priority | LOG_DAEMON, "%s", message_part);
		g_free(message_part);
	}
	if (mem){
		g_free(VmSize);
		g_free(VmRSS);
		g_free(VmData);
		g_free(VmStk);
		g_free(VmLib);
	}
	
    //syslog( priority | LOG_DAEMON, message );

    if (log_level & G_LOG_FLAG_FATAL) exit_signal = -1;
}

void initialize_log (void) 
{
	int level;
	
	if (strncmp( CONF("LogFacility"), "syslog", 6 ) == 0)
	{
		unsigned int wsk_log_level = CONFd("wsk_log_level");
		
		switch (wsk_log_level){
			
			case 1:
				level = G_LOG_LEVEL_ERROR;
				break;
			case 3:
				level = (G_LOG_LEVEL_ERROR | G_LOG_LEVEL_WARNING);
				break;
			case 7:
				level = (G_LOG_LEVEL_ERROR | G_LOG_LEVEL_WARNING | G_LOG_LEVEL_MESSAGE);
				break;
			case 15:
				level = (G_LOG_LEVEL_ERROR | G_LOG_LEVEL_WARNING | G_LOG_LEVEL_MESSAGE | G_LOG_LEVEL_INFO);
				break;
			case 31:
			default:
				level = (G_LOG_LEVEL_ERROR | G_LOG_LEVEL_WARNING | G_LOG_LEVEL_MESSAGE | G_LOG_LEVEL_INFO | G_LOG_LEVEL_DEBUG);
				break;
		}

		openlog(CONF("SyslogIdent"), LOG_CONS | LOG_PID, LOG_DAEMON );	
		g_log_set_handler( 0,(GLogLevelFlags)(level | G_LOG_FLAG_RECURSION | G_LOG_FLAG_FATAL),g_syslog,0);
	}
}

/************* main ************/

int main(int argc, char** argv)
{
	GMainLoop  *loop;
	GIOChannel *sock, *sock6;

	/* read sicat.conf */

	nocat_conf = read_conf_file( NC_CONF_PATH "/sicat.conf" );
	
	if (nocat_conf == NULL) {
		
		//g_error("could not read the config file, aborting program...");
		return -1;
	}
	
	if (argc < 2 || strncmp(argv[1], "-D", 2) != 0) daemonize();
	
	/* initalize the log */

	initialize_log();

	/* set network parameters */
	set_network_defaults(nocat_conf);

	/* initialize the firewall */
	fw_init(nocat_conf);

	/* initialize the peer table */
	peer_tab = g_hash_new();

	/* initialize the listen socket */
	sock = http_bind_socket( CONF("GatewayAddr"), CONFd("GatewayPort"), CONFd("ListenQueue"));
	
	if (CONFd("IPv6")) sock6 = http_bind_socket6( "in6addr_any", CONFd("GatewayPort"), CONFd("ListenQueue"));

	/* create and initialize the websocket comunication interface */
	
	macAddressFrom = get_mac_address(CONF("ExternalDevice"));
	
	wsk_comm_interface = NULL;
	
	if (CONFd("usewsk")){
		wsk_comm_interface = new class comm_interface();
		if (wsk_comm_interface == NULL){
		
			g_error("main: websocket initialization error, aborting program...");
			return -1;
		}
	}
	
	//requests = g_new0(h_requests,1);

	/* initialize the main loop and handlers */
	loop = g_main_loop_new(NULL,FALSE);

	g_io_add_watch( sock, G_IO_IN, (GIOFunc) handle_accept,NULL);
	if (CONFd("IPv6")) g_io_add_watch( sock6, G_IO_IN, (GIOFunc) handle_accept6,NULL);
	g_timeout_add( 30000, (GSourceFunc) check_peers, NULL );
	g_timeout_add( 1000, (GSourceFunc) check_exit_signal, loop );
    
	/* Go! */
	g_message("main: starting main loop");
	//g_main_run( loop );
	g_main_loop_run(loop);
	g_message("main: exiting main loop");
	
	return 0;
}
