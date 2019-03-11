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
			function_name , fd, r2, remote_port, localaddr_ip, local_port);

	return TRUE;

}

/************ Check peer timeouts **************/

gboolean check_peers( void *dummy ) {

	time_t now = time(NULL);
	//g_message("Checking peers for expiration");
	g_hash_table_foreach_remove( peer_tab, (GHRFunc)check_peer_expire, &now );
	//g_hash_table_foreach( peer_tab, (GHFunc)check_peer_expire, &now );
	return TRUE;
}

gboolean change_table( void *dummy ) {

	if ( strcmp(table,"0") == 0) strcpy(table,"1");
	else strcpy(table,"0");
	fw_resettable (nocat_conf);

	return TRUE;
}

/************* Connection handlers ************/

/************* Read Input Data Connection handle *******/
gboolean handle_read( GIOChannel *sock, GIOCondition cond, http_request *h ) {
	
	//g_debug("handle_read: reading request fd = %d",g_io_channel_unix_get_fd (h->sock));

	guint r;
	
	r= http_request_read(h);
	
	if (r == 1){

		http_request_ok(h);
			
		if (handle_request(h) == 0) {
			
			g_debug("handle_read: leaving without shutting down request fd = %d",g_io_channel_unix_get_fd (h->sock));
			return TRUE;
		}
	
	}
	else if (r == 0) {
		
		g_debug("handle_read: leaving without shutting down request fd = %d",g_io_channel_unix_get_fd (h->sock));
		return TRUE;
	}
	
	//g_debug("handle_read: shutting down request fd = %d",g_io_channel_unix_get_fd (h->sock));

	g_io_channel_shutdown(h->sock,TRUE,NULL);
	g_io_channel_unref(h->sock );
	http_request_free(h);

	return FALSE;
}

/************* Accept Connection handle *******/
gboolean handle_accept( GIOChannel* sock, GIOCondition cond,  void* dummy ) {

	GIOChannel* conn;
	http_request* req; /* defined in http.h */
	int fd,n;
	pid_t mypid;
	

	//g_debug ("handle_accept: entering..");
	fd = accept( g_io_channel_unix_get_fd(sock), NULL, NULL );

	n = fcntl( fd, F_GETFL, 0 );
    fcntl( fd, F_SETFL, n | O_NONBLOCK);
    
    mypid = getpid();
    fcntl( fd, F_SETOWN, mypid);
	
	conn = g_io_channel_unix_new( fd );
	
	//g_io_channel_set_encoding(conn,NULL,&gerror);
	
	g_io_channel_set_close_on_unref(conn,TRUE);
	g_io_channel_set_buffer_size(conn,4096);
	
	req  = http_request_new( conn, fd );
	
	if (req != NULL){
		
		//show_socket_pairs((char*)"handle_accept", req);
		req->source_id = g_io_add_watch(req->sock, G_IO_IN,(GIOFunc)handle_read, req);
		
	}
	else {
		
		g_io_channel_shutdown(conn,FALSE,NULL);
		g_io_channel_unref(conn);
		
	}
	
	
	//g_debug ("handle_accept: leaving..");
	return TRUE;
}

gboolean handle_accept6( GIOChannel* sock, GIOCondition cond,  void* dummy ) {

	GIOChannel* conn;
	http_request* req; /* defined in http.h */
	int fd,n;
	pid_t mypid;

	fd = accept( g_io_channel_unix_get_fd(sock), NULL, NULL );

	/* The line below need to be substituted by other error checking method that don't break daemon execution*/
	//g_assert( fd != -1 );
	
	n = fcntl( fd, F_GETFL, 0 );
    //if (n == -1) g_error("fcntl F_GETFL on %s: %m", ip );
    //g_message("n = %d",n);
    
    //g_message("O_NONBLOCK modified = %d",n & O_NONBLOCK);
    
    fcntl( fd, F_SETFL, n | O_NONBLOCK);

	//if (r == -1) g_error("fcntl F_SETFL O_NDELAY on %s: %m", ip );
    
    mypid = getpid();
    fcntl( fd, F_SETOWN, mypid);
	
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

gboolean check_exit_signal( GMainLoop *loop ) {
	
	pid_t my_pid;
	gchar* nombre;
	gchar* contenido;
	gsize length;
	gchar *start_memory, *end_memory;
	gchar *VmSize;
	unsigned int memory_size;
	gint64 memory_used;
	
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
	g_strcanon(VmSize,"0123456789",'\0');
	
	memory_used = g_ascii_strtoll(VmSize,NULL,0);
	
	//g_debug("memoria total usada %d",memory_used);
	
	g_free(contenido);
	g_free(VmSize);
	
	if (memory_used > CONFd("memlimit")){
		
		g_message( "check_exit_signal: memory usage exceded, exiting");
		fclose(log_fd);
		g_main_quit( loop );
		return TRUE;
	}
    
    if (exit_signal) {
		
		g_message( "check_exit_signal: Caught exit signal %d!", exit_signal );
		if (pid_file != NULL) {
		    unlink( NC_PID_FILE );
		    fclose( pid_file );
		}
		g_remove("/tmp/sicat.tmp");
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
		g_strcanon(VmSize,"0123456789",'\0');
		
		start_memory = g_strstr_len(contenido,-1,"VmRSS:");
		end_memory = g_strstr_len(contenido,-1,"VmData:");
		memory_size = end_memory - start_memory - 8;
		VmRSS = g_strndup(start_memory+7,memory_size);
		g_strchug(VmRSS);
		g_strcanon(VmRSS,"0123456789",'\0');
		
		start_memory = g_strstr_len(contenido,-1,"VmData:");
		end_memory = g_strstr_len(contenido,-1,"VmStk:");
		memory_size = end_memory - start_memory - 9;
		VmData = g_strndup(start_memory+8,memory_size);
		g_strchug(VmData);
		g_strcanon(VmData,"0123456789",'\0');
		
		start_memory = g_strstr_len(contenido,-1,"VmStk:");
		end_memory = g_strstr_len(contenido,-1,"VmExe:");
		memory_size = end_memory - start_memory - 8;
		VmStk = g_strndup(start_memory+7,memory_size);
		g_strchug(VmStk);
		g_strcanon(VmStk,"0123456789",'\0');
		
		start_memory = g_strstr_len(contenido,-1,"VmLib:");
		end_memory = g_strstr_len(contenido,-1,"VmPTE:");
		memory_size = end_memory - start_memory - 8;
		VmLib = g_strndup(start_memory+7,memory_size);
		g_strchug(VmLib);
		g_strcanon(VmLib,"0123456789",'\0');
		
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
			if ( i == 0) {
				syslog( priority | LOG_DAEMON, "%s-%s-%s-%s-%s-- %s",VmSize,VmRSS,VmData,VmStk,VmLib,message_part);
				if (log_fd != NULL){
					fprintf (log_fd, "%s-%s-%s-%s-%s-- %s",VmSize,VmRSS,VmData,VmStk,VmLib, strcat (message_part, "\n"));
					fflush (log_fd);
				}
				
			}
			else {
				syslog( priority | LOG_DAEMON, "%s", message_part);
				if (log_fd != NULL){
					fprintf (log_fd, "%s",strcat (message_part, "\n"));
					fflush (log_fd);
				}
			}
		}
		else {
			syslog(priority | LOG_DAEMON, "%s", message_part);
			if (log_fd != NULL){
				fprintf (log_fd, "%s",strcat (message_part, "\n"));
				fflush (log_fd);
			}
		}
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

FILE * initialize_log (void) 
{
	int level;
	FILE* fd;
	
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
	
	if (strncmp( CONF("LogFacility"), "syslog", 6 ) == 0)
	{
		openlog(CONF("SyslogIdent"), LOG_CONS | LOG_PID, LOG_DAEMON );	
		g_log_set_handler( 0,(GLogLevelFlags)(level | G_LOG_FLAG_RECURSION | G_LOG_FLAG_FATAL),g_syslog,0);
		fd = NULL;
	}
	else {
		
		openlog(CONF("SyslogIdent"), LOG_CONS | LOG_PID, LOG_DAEMON );	
		g_log_set_handler( 0,(GLogLevelFlags)(level | G_LOG_FLAG_RECURSION | G_LOG_FLAG_FATAL),g_syslog,0);
		fd = fopen (CONF("LogFacility"), "a");
		//fprintf (fd, "%s",strcat ("iniciando una corrida de sicat", "\n\n"));
		//fflush (fd);
	}
	return fd;
}

void peer_arp_dns(gchar* ip_add, gchar* hw_add) {
    gchar ip[50], hw[18];
    FILE *arp;

    arp = fopen( "/proc/net/arp", "r" );
    if ( arp == NULL ){
    	g_warning( "Can't open /proc/net/arp: %m" );
    	return;
    }
   
    fscanf(arp, "%*s %*s %*s %*s %*s %*s %*s %*s %*s"); // Skip first line 
    while (fscanf( arp, "%15s %*s %*s %17s %*s %*s\n", ip, hw ) != EOF){
		if (strcmp( ip_add, ip) == 0 ) 
			{
				g_strncpy(hw_add, hw, sizeof(hw) );
				break;
			}
    }

    fclose( arp );

}

static int nfq_http_callback(struct nfq_q_handle *qh,struct nfgenmsg *nfmsg,struct nfq_data *nfad, void *data){
	
	int id,n;
	unsigned char *payload;
	struct nfq_iphdr* ip_header;
	struct nfq_tcphdr* tcp_header;
	gchar ip_dest[16];
	gchar ip_source[16];
	gchar hw[18];
	peer* p;
	//uint32_t** temp_addresses;
	//struct sockaddr_in aa;
	
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
	id = ntohl(ph->packet_id);
	
	n = nfq_get_payload(nfad,&payload);
	ip_header = (struct nfq_iphdr*) payload;

	inet_ntop(AF_INET, &ip_header->saddr, ip_source, 16);
	
	peer_arp_dns(ip_source, hw);
	
	p = (peer*) g_hash_table_lookup(peer_tab, hw);
	
	inet_ntop(AF_INET, &ip_header->daddr, ip_dest,16);
	
	g_debug("nfq_http_callback: captured output ip package from %s to %s",ip_source,ip_dest);

	if (p != NULL){
		
		if ((p->status == 0) || (p->status == 2) || (p->status == 3)){	// Aqu'i el peer se est'a autentificando en cualquiera de los dos
																		// statuses para eso (0 o 2) o est'a permitido ya (status == 3)
			
			//g_debug("el peer est'a en modo 0, 2 'o 3, se deja pasar el paquete ip..");
			nfq_set_verdict2(qh, id, NF_ACCEPT, 3 ,0, NULL);
			return 0;
		}
		else if (p->status == 1) {	// El peer est'a castigado, as'i que se devuelve el paquete sin marcar 
									// para que se atrape (si es http), si es https se descarta
		
			tcp_header = (struct nfq_tcphdr*) (payload + (ip_header->ihl * 4));
								
			if ( ntohs(tcp_header->dest) == 80 ) {
				
				//g_debug("nfq_http_callback: el peer est'a castigado, se deja pasar http para que se capture el cliente");
				nfq_set_verdict(qh, id, NF_ACCEPT,0, NULL);
				return 0;
			}
			else  {
				
				//g_debug("nfq_http_callback: el peer est'a castigado, no se deja pasar https");
				nfq_set_verdict(qh, id, NF_DROP,0, NULL);
				return 0;
			}	
		}
	}
	else  {
		
		tcp_header = (struct nfq_tcphdr*) (payload + (ip_header->ihl * 4));
								
		if ( ntohs(tcp_header->dest) == 80 ) {
			
			//g_debug("nfq_http_callback: el peer no existe, se deja pasar http para que se capture el cliente");
			nfq_set_verdict(qh, id, NF_ACCEPT,0, NULL);
			return 0;
		}
		else {
			
			//g_debug("nfq_http_callback: el peer no existe, no se deja pasar https");
			nfq_set_verdict(qh, id, NF_DROP,0, NULL);
			return 0;
		}
	}
	return 0;
}

static int nfq_http_input_callback(struct nfq_q_handle *qh,struct nfgenmsg *nfmsg,struct nfq_data *nfad, void *data){
	
	int id,n;
	unsigned char *payload;
	struct nfq_iphdr* ip_header;
	//struct nfq_tcphdr* tcp_header;
	gchar ip_dest[16];
	gchar ip_source[16];
	gchar hw[18];
	peer* p;
	//uint32_t** temp_addresses;
	//struct sockaddr_in aa;
	
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
	id = ntohl(ph->packet_id);
	
	n = nfq_get_payload(nfad,&payload);
	ip_header = (struct nfq_iphdr*) payload;

	//g_debug("ip version = %u",(unsigned int)ip_header->version);
	//g_debug("ip header lenght = %u",(unsigned int)ip_header->ihl);
	
	//g_debug("payload size = %d",n);
	//g_debug("ip header lenght = %u",ntohs(ip_header->tot_len));

	inet_ntop(AF_INET, &ip_header->saddr, ip_source, 16);	
	inet_ntop(AF_INET, &ip_header->daddr, ip_dest, 16);
	//g_debug("nfq_http_input_callback: captured input ip package from %s to %s",ip_source,ip_dest);

	/*for (int i = 0; i < n; i++) {
		g_debug(" 0x%1X ", payload[i] );
		//g_debug(" %d ", payload[i] );
	}*/
	
	peer_arp_dns(ip_dest, hw);
	
	//g_debug("http request hw source address = %s",hw);
	p = (peer*) g_hash_table_lookup(peer_tab, hw);
	
	if (p != NULL){
		
		if ((p->status == 0) || (p->status == 2)){
			
			if (strcmp(ip_source,datalnet_IP) == 0) { //Esto es tr'afico que viene desde datalnet, por lo tanto se incrementa el contador bueno.
			
				p->current_time = time(NULL);
				p->contador_b++;
				//g_debug("contador_b = %u",p->contador_b);
				//g_debug("contador_m = %u",p->contador_m);
			}
			else {
				p->contador_m++;
				//g_debug("contador_b = %u",p->contador_b);
				//g_debug("contador_m = %u",p->contador_m);
			}
			
			nfq_set_verdict(qh, id, NF_ACCEPT,0, NULL);
			return 0;
		}
		else if (p->status == 1) {	// El peer est'a castigado, no se deja pasar el tr'afico de entrada
			
			nfq_set_verdict(qh, id, NF_DROP,0, NULL);
			return 0;
		}
		else if (p->status == 3) {
			
			nfq_set_verdict(qh, id, NF_ACCEPT,0, NULL);
			return 0;
		}
	}
	else {
		
		//g_debug("nfq_http_input_callback: el peer no existe, no se deja pasar nada");
		nfq_set_verdict(qh, id, NF_DROP,0, NULL);
		return 0;
	}
	return 0;
}

gboolean handle_http( GIOChannel *sock, GIOCondition cond, void* dummy  ){
	
	char buf[4096] __attribute__ ((aligned));
	int r;
		 
	r = recv(g_io_channel_unix_get_fd (sock), buf, sizeof(buf) , 0);
	//g_debug("handle_http: datos recibidos = %d",r); 
	nfq_handle_packet(http_queue_handle, buf, r);
	
	return TRUE;	
}

gboolean handle_http_input( GIOChannel *sock, GIOCondition cond, void* dummy  ){
	
	char buf[4096] __attribute__ ((aligned));
	int r;
		 
	r = recv(g_io_channel_unix_get_fd (sock), buf, sizeof(buf) , 0);
	nfq_handle_packet(http_input_queue_handle, buf, r);
	
	return TRUE;	
}

/************* main ************/

int main(int argc, char** argv)
{
	GMainLoop  *loop;
	GIOChannel *sock, *sock6, *sock_http, *sock_http_input;
	int ret;

	/* read sicat.conf */
	
	nocat_conf = read_conf_file( NC_CONF_PATH "/sicat.conf" );
	
	if (nocat_conf == NULL) {
		
		openlog("SiCat", LOG_CONS | LOG_PID, LOG_DAEMON );
		syslog( LOG_ERR | LOG_DAEMON, "could not read the config file, aborting program...");
		return -1;
	}
	
	if (argc < 2 || strncmp(argv[1], "-D", 2) != 0) daemonize();
	
	/* initalize the log */

	log_fd = initialize_log();

	/* set network parameters */
	set_network_defaults(nocat_conf);

/***************************** Initialize the http output queue *******************************************/

	http_queue_handle = nfq_open();
	if (!http_queue_handle) {
		g_error("error during nfq_open() for http_output_handle");
	}
	if (nfq_unbind_pf(http_queue_handle, AF_INET) < 0) {
		g_error("error during nfq_unbind_pf() for http_output_handle");
	}
	if (nfq_bind_pf(http_queue_handle, AF_INET) < 0) {
		g_error("error during nfq_bind_pf() for http_output_handle");
	}
	http_q_queue_handle = nfq_create_queue(http_queue_handle, 0, &nfq_http_callback, NULL);
	if (!http_q_queue_handle) {
		g_error("error during nfq_create_queue() for http_output_handle");
	}
	if (nfq_set_mode(http_q_queue_handle, NFQNL_COPY_PACKET, 0xffff) < 0) {
		g_error("can't set packet_copy mode for http_output_handle");
	}
	
	sock_http = g_io_channel_unix_new(nfq_fd(http_queue_handle));
	g_io_channel_set_encoding(sock_http,NULL,NULL);
	
	g_io_add_watch(sock_http, G_IO_IN, (GIOFunc) handle_http,NULL);

/***********************************************************************************************************/

/***************************** Initialize the http input queue *******************************************/

	http_input_queue_handle = nfq_open();
	if (!http_input_queue_handle) {
		g_error("error during nfq_open() for http_input_handle");
	}
	if (nfq_unbind_pf(http_input_queue_handle, AF_INET) < 0) {
		g_error("error during nfq_unbind_pf() for http_input_handle");
	}
	if (nfq_bind_pf(http_input_queue_handle, AF_INET) < 0) {
		g_error("error during nfq_bind_pf() for http_input_handle");
	}
	http_input_q_queue_handle = nfq_create_queue(http_input_queue_handle, 1, &nfq_http_input_callback, NULL);
	if (!http_input_q_queue_handle) {
		g_error("error during nfq_create_queue() for http_input_handle");
	}
	if (nfq_set_mode(http_input_q_queue_handle, NFQNL_COPY_PACKET, 0xffff) < 0) {
		g_error("can't set packet_copy mode for intput handle");
	}
	
	sock_http_input = g_io_channel_unix_new(nfq_fd(http_input_queue_handle));
	g_io_channel_set_encoding(sock_http_input,NULL,NULL);
	
	g_io_add_watch(sock_http_input, G_IO_IN, (GIOFunc)handle_http_input,NULL);

/***********************************************************************************************************/


	/* initialize the firewall */
	
	if (!g_file_test("/tmp/sicat.tmp",G_FILE_TEST_EXISTS)) {
	
		fw_init(nocat_conf);
		ret = creat("/tmp/sicat.tmp",O_RDWR);
		if (ret == -1) return -1;
		close(ret);
	}
	
	/* initialize the peer table */
	peer_tab = g_hash_new();

	/* initialize the listen socket */
	sock = http_bind_socket( CONF("GatewayAddr"), CONFd("GatewayPort"), CONFd("ListenQueue"));
	
	if (CONFd("IPv6")) sock6 = http_bind_socket6( "in6addr_any", CONFd("GatewayPort"), CONFd("ListenQueue"));

	/* create and initialize the websocket comunication interface */
	
	macAddressFrom = get_mac_address(CONF("ExternalDevice"));
	
	wsk_comm_interface = NULL;
	datalnet_IP = NULL;
	
	if (CONFd("usewsk")){
		wsk_comm_interface = new class comm_interface();
		if (wsk_comm_interface == NULL){
		
			g_error("main: websocket initialization error, aborting program...");
			return -1;
		}
	}
	
	/* initialize the main loop and handlers */
	loop = g_main_loop_new(NULL,FALSE);

	g_io_add_watch( sock, G_IO_IN, (GIOFunc) handle_accept,NULL);
	if (CONFd("IPv6")) g_io_add_watch( sock6, G_IO_IN, (GIOFunc) handle_accept6,NULL);
	
	table = g_new0(gchar,10);
	strcpy(table,"0");
	
	g_timeout_add( ((CONFd("LoginTimeout")*1000) + 60000), (GSourceFunc) change_table, NULL );
	g_timeout_add( 1000, (GSourceFunc) check_exit_signal, loop );
	g_timeout_add( 1000, (GSourceFunc) check_peers, NULL );
    
	/* Go! */
	g_message("main: starting main loop");
	//g_main_run( loop );
	g_main_loop_run(loop);
	g_message("main: exiting main loop");
	
	return 0;
}
