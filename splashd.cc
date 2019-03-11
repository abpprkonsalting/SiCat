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

gboolean change_table( void *dummy ) {

	if ( strcmp(table,"0") == 0) strcpy(table,"1");
	else strcpy(table,"0");
	fw_resettable (nocat_conf);

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
			
		handle_request(h);
	
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
	int fd,n;
	pid_t mypid;
	guint sourc_id;
	

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
		
		show_socket_pairs((char*)"handle_accept", req);
		sourc_id = g_io_add_watch(conn, G_IO_IN,(GIOFunc)handle_read, req);
		//g_debug("source_id before= %d",sourc_id);
		req->source_id = sourc_id;
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


gboolean check_exit_signal ( GMainLoop *loop ) {
	
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
		 fclose (log_fd);
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

FILE * initialize_log (void) {
	
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
	
	int id, n;
	char *payload;
	struct nfq_iphdr* ip_header;
	struct nfq_tcphdr* tcp_header;
	gchar ip[16];
	gchar hw[18];
	peer* p;
	
	g_message("lleg'o una solicitud http desde un cliente");
	
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
	if (ph)	id = ntohl(ph->packet_id);
	
	n = nfq_get_payload(nfad,(unsigned char**)&payload);
	ip_header = (struct nfq_iphdr*) payload;

	g_debug("ip version = %u",(unsigned int)ip_header->version);
	g_debug("ip header lenght = %u",(unsigned int)ip_header->ihl);
	
	//g_debug("payload size = %d",n);
	//g_debug("ip header lenght = %u",ntohs(ip_header->tot_len));

	inet_ntop(AF_INET, &ip_header->saddr, ip, 16);
	g_debug("http request ip source address = %s",ip);
	
	peer_arp_dns(ip, hw);
	
	g_debug("http request hw source address = %s",hw);
	p = (peer*) g_hash_table_lookup(peer_tab, hw);
	
	inet_ntop(AF_INET, &ip_header->daddr, ip, 16);
	g_debug("http request ip destination address = %s",ip);

	
	/*for (int i = 0; i < n; i++) {
		g_debug(" 0x%1X ", payload[i] );
		//g_debug(" %d ", payload[i] );
	}*/
	
	if (p != NULL){
		
		int i = 0;
		
		switch (p->autentication_stage){
			
			case 0:
			
				g_debug("el peer a'un no est'a en fase de autentificaci'on, se ignora..");
				nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
				break;
			
			case 1:
				g_debug("peer en fase 1 de autentificaci'on, chequeando el paquete ip contra los sitios de la fase 1");
				
				while (p->tabla_sitios[i] != NULL){
					
					if (p->tabla_sitios[i]->autentication_stage != 1) break;
					
					for (int j=0;j<(int)p->tabla_sitios[i]->ip_v4_addresses;j++){
						
						if ( *(p->tabla_sitios[i]->ip_v4[j]) == ip_header->daddr) {
							
							g_debug("el paquete va a un sitio permitido para la fase 1, se deja pasar");
							
							// Lo que viene abajo es la comprobaci'on de si este paquete lleva la solicitud a datalnet
							// de que comience el proceso de log'in en un m'etodo de autentificaci'on determinado
							
							//tcp_header = (struct nfq_tcphdr*) (payload + sizeof(*ip_header));
							tcp_header = (struct nfq_tcphdr*) (payload + (ip_header->ihl * 4));
							
							//g_debug("puerto destino del paquete = %d",ntohs(tcp_header->dest));
							
							//Chequear que es un paquete http, no ssl
							if ( ntohs(tcp_header->dest) == 80 ) {
								
								
								/*unsigned int size = (n - (ip_header->ihl * 4) - sizeof(*tcp_header));
								gchar* buf_temp = g_strndup( (gchar*)(payload + (ip_header->ihl * 4) + sizeof(*tcp_header)),
                                                         size);*/
								
								if ((g_strstr_len((gchar*)(payload + (ip_header->ihl * 4) + sizeof(*tcp_header)),
											(n - (ip_header->ihl * 4) - sizeof(*tcp_header)),
											"/Account/ExternalLogin?userMac=") != NULL) && 
											( strcmp( p->tabla_sitios[i]->name, CONF("AuthServiceAddr")) == 0)){
												
									g_debug("nfq_http_callback: peer %s en proceso de autentificación, stage 2...", p->ip);
									p->autentication_stage = 2;												
								}

								/*
								http_request* h = g_new0(http_request, 1);
								h->source_id = 0;
								inet_ntop(AF_INET, &ip_header->saddr, h->peer_ip, 16);
								inet_ntop(AF_INET, &ip_header->daddr, h->sock_ip, 16);
								peer_arp_dns(h->peer_ip, h->hw);
								
								unsigned int size = (n - sizeof(*ip_header) - sizeof(*tcp_header));
								gchar* buf_temp = g_strndup( (gchar*)(payload + sizeof(*ip_header) + sizeof(*tcp_header)),
                                                         size);
								
								h->buffer = g_string_new("");
								g_string_append(h->buffer, buf_temp);
								g_free(buf_temp);
								
								gchar *header_end = strstr( h->buffer->str,"\r\n\r\n" );
		
								if (header_end != NULL) {
									
									http_parse_header(h, h->buffer->str);
									http_parse_query (h, NULL);
									
									if ((strcmp( h->uri, "/Account/ExternalLogin" ) == 0) ){//& 
												//( QUERY("provider") != NULL || QUERY("provider.x") != NULL ) ) {
								
										g_debug("nfq_http_callback: peer %s en proceso de autentificación, stage 2...", p->ip);
								
										p->autentication_stage = 2;
									}
								}
								else {
								
									g_debug("nfq_http_callback: El mensaje http lleg'o fragmentado, no se anal'iza..");
								}
								*/
								
							}
							nfq_set_verdict2(qh, id, NF_ACCEPT, 3 ,0, NULL);
							return 0;
						}
					}
					i++;
				}
				// Si se lleg'o aqu'i es porque el paquete no iba a uno de los sitios permitidos en el proceso de autentificaci'on,
				// por lo tanto se deja pasar el paquete pero no se marca, para que m'as adelante sea capturado.
				
				nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
				break;
			case 2:
				
				g_debug("peer en fase 2 de autentificaci'on, chequeando el paquete ip contra los sitios de la fase 1 y 2");
				
				while (p->tabla_sitios[i] != NULL){
					
					//if (p->tabla_sitios[i]->autentication_stage != 2) break;
					//g_debug("e");
					
					for (int j=0;j<(int)p->tabla_sitios[i]->ip_v4_addresses;j++){
						
						//g_debug("direcci'on en la tabla = %d",*(p->tabla_sitios[i]->ip_v4[j]));
						//g_debug("direcci'on del paquete = %d",ip_header->daddr);
						
						if ( *(p->tabla_sitios[i]->ip_v4[j]) == ip_header->daddr) {
							
							g_debug("el paquete va a un sitio permitido para la fase 2, se deja pasar");
							nfq_set_verdict2(qh, id, NF_ACCEPT, 3 ,0, NULL);
							return 0;
						}
					}
					i++;
				}
				nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);				
				break;
			case 3:
				
				break;
			default:
				
				break;
		}
	}
	else {
		
		g_debug("el peer no existe");
		nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
	return 0;
}

static int nfq_output_callback(struct nfq_q_handle *qh,struct nfgenmsg *nfmsg,struct nfq_data *nfad, void *data){
	
	int id, n;
	char *payload;
	gchar ip[16];
	gchar hw[18];
	struct DNS_PACKAGE* DNSpackage;
	peer* p;
	struct nfq_iphdr* ip_header;
	
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
	if (ph)	id = ntohl(ph->packet_id);
	
	//g_message("lleg'o una respuesta DNS desde el servidor DNS");
	
	n = nfq_get_payload(nfad,(unsigned char**)&payload);
	
	ip_header = (struct nfq_iphdr*) payload;
	
	inet_ntop(AF_INET, &ip_header->daddr, ip, 16);
	//g_debug("DNS package ip destination address = %s",ip);
	
	peer_arp_dns(ip, hw);
	
	//g_debug("DNS package hw destination address = %s",hw);
		
	p = (peer*) g_hash_table_lookup(peer_tab, hw);
	
	if (p != NULL){	// Esto significa que el peer existe en el sistema, por lo tanto se est'a autenticando
					// y es pertinente saber que es lo que va a buscar en internet por DNS.
	
		DNSpackage = parse_DNS_message(payload,n);
		
		// Se chequea el mensaje DNS si contiene respuestas, si no no es necesario chequearlo pues lo que buscamos es precisamente
		// las respuestas a las solicitudes DNS.
		
		if (ntohs(DNSpackage->dns_header->ans_count) > 0) {
			
			bool at_least_one = FALSE;
			
			int i = 0;
			while ((p->tabla_sitios[i] != NULL) && (at_least_one == FALSE)) {	// Esto se hace para cada sitio de la tabla
				
					g_debug("checking site name = %s",p->tabla_sitios[i]->name);
																										 				
					if (ntohs(DNSpackage->dns_header->q_count) > 0) {
						
						/*gchar* str1 = g_strdup((gchar*)p->tabla_sitios[i]->name);
						g_strreverse(str1);
						gchar* str2 = g_strdup((gchar*)DNSpackage->dns_queries[0]->name);
						g_strreverse(str2);*/
						
						//if (strncmp(str1,str2,13) == 0) {
						//if (strcmp((gchar*)p->tabla_sitios[i]->name,(gchar*)DNSpackage->dns_queries[0]->name) == 0) {
						
						// Aqu'i comparo si lo que lleg'o termina en el nombre que tengo guardado en la tabla, esto es para
						// poder poner dominios en la tabla.
						if (g_str_has_suffix((gchar*)DNSpackage->dns_queries[0]->name,(gchar*)p->tabla_sitios[i]->name)) {
							
							if ( p->tabla_sitios[i]->autentication_stage == p->autentication_stage){ // Si el sitio de la tabla se corresponde con la etapa 
																									// de autentificaci'on en que se encuentra el peer.
							
				
								for(int j = 0;j<ntohs(DNSpackage->dns_header->ans_count);j++){	// Para cada respuesta que lleg'o en el paquete DNS
									
									if(ntohs(DNSpackage->dns_answers[j]->resource->type) == 1) {	// Si tipo de respuesta es una direcci'on ipv4
										
										long *p1;
										struct sockaddr_in a;
										p1=(long*)DNSpackage->dns_answers[j]->rdata;
										//a.sin_addr.s_addr=(*p1);
		
										uint32_t** temp_addresses = g_new0(uint32_t*,p->tabla_sitios[i]->ip_v4_addresses + 1 );
										
										for (unsigned int l=0;l < p->tabla_sitios[i]->ip_v4_addresses;l++) temp_addresses[l] = p->tabla_sitios[i]->ip_v4[l];
										
										g_free(p->tabla_sitios[i]->ip_v4);
		
										p->tabla_sitios[i]->ip_v4 = temp_addresses;
										
										p->tabla_sitios[i]->ip_v4[p->tabla_sitios[i]->ip_v4_addresses] = g_new0(uint32_t,1);
										
										p->tabla_sitios[i]->ip_v4_addresses++;
										
										memcpy(p->tabla_sitios[i]->ip_v4[p->tabla_sitios[i]->ip_v4_addresses - 1],p1,sizeof(uint32_t));
										//strcpy(p->tabla_sitios[i]->ip_v4[p->tabla_sitios[i]->ip_v4_addresses - 1],inet_ntoa(a.sin_addr));
										
										a.sin_addr.s_addr=(*p->tabla_sitios[i]->ip_v4[p->tabla_sitios[i]->ip_v4_addresses - 1]);
										g_debug("direccion ip_v4 # %d del sitio %s = %s",p->tabla_sitios[i]->ip_v4_addresses,
												p->tabla_sitios[i]->name,inet_ntoa(a.sin_addr));
										
										at_least_one = TRUE;
			
									}				
								}
							}
							else {
								
								g_debug("la solicitud dns es de un sitio cuya fase de autentificaci'on a'un no ha comenzado");
								free_DNS_message(DNSpackage);
								nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
							}
						}
						//g_free(str1);
						//g_free(str2);
					}
					else g_debug("El paquete dns no trae queries");
				///////////////}
				
				i++;
			}
		}
		
		free_DNS_message(DNSpackage);	
	}
	//else g_debug("La solicitud DNS no fue de un peer, se ignora..");

	nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	
	return 0;
}

gboolean handle_http( GIOChannel *sock, GIOCondition cond, void* dummy  ){
	
	char buf[4096] __attribute__ ((aligned));
	int r;
		 
	r = recv(g_io_channel_unix_get_fd (sock), buf, sizeof(buf) , 0);
	g_debug("handle_http: datos recibidos = %d",r); 
	nfq_handle_packet(http_queue_handle, buf, r);
	
	return TRUE;
		
}

gboolean handle_output( GIOChannel *sock, GIOCondition cond, void* dummy  ){
	
	char buf[4096] __attribute__ ((aligned));
	int r;
		 
	r = recv(g_io_channel_unix_get_fd (sock), buf, sizeof(buf) , 0); 
	nfq_handle_packet(output_queue_handle, buf, r);
	
	return TRUE;
		
}

/************* main ************/

int main(int argc, char** argv)
{
	GMainLoop  *loop;
	GIOChannel *sock, *sock6, *sock_http, *sock_DNS1;
	int ret;
	int n;
	pid_t mypid;

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
	
	/* Initialize the input http queue */
	
	http_queue_handle = nfq_open();
	if (!http_queue_handle) {
		g_error("error during nfq_open() for http_handle");
	}
	if (nfq_unbind_pf(http_queue_handle, AF_INET) < 0) {
		g_error("error during nfq_unbind_pf() for http_handle");
	}
	if (nfq_bind_pf(http_queue_handle, AF_INET) < 0) {
		g_error("error during nfq_bind_pf() for http_handle");
	}
	http_q_queue_handle = nfq_create_queue(http_queue_handle, 0, &nfq_http_callback, NULL);
	if (!http_q_queue_handle) {
		g_error("error during nfq_create_queue() for http_handle");
	}
	if (nfq_set_mode(http_q_queue_handle, NFQNL_COPY_PACKET, 0xffff) < 0) {
		g_error("can't set packet_copy mode for intput handle");
	}
	
	sock_http = g_io_channel_unix_new(nfq_fd(http_queue_handle));
	g_io_channel_set_encoding(sock_http,NULL,NULL);
	
	g_io_add_watch(sock_http, G_IO_IN, (GIOFunc) handle_http,NULL);
	
	/* Initialize the output DNS queue */
	
	output_queue_handle = nfq_open();
	if (!output_queue_handle) {
		g_error("error during nfq_open() for output_handle");
	}
	if (nfq_unbind_pf(output_queue_handle, AF_INET) < 0) {
		g_error("error during nfq_unbind_pf() for output_handle");
	}
	if (nfq_bind_pf(output_queue_handle, AF_INET) < 0) {
		g_error("error during nfq_bind_pf() for output_handle");
	}
	output_q_queue_handle = nfq_create_queue(output_queue_handle, 1, &nfq_output_callback, NULL);
	if (!output_q_queue_handle) {
		g_error("error during nfq_create_queue() for output_handle");
	}
	if (nfq_set_mode(output_q_queue_handle, NFQNL_COPY_PACKET, 0xffff) < 0) {
		g_error("can't set packet_copy mode for intput handle");
	}
	sock_DNS1 = g_io_channel_unix_new(nfq_fd(output_queue_handle));
	g_io_channel_set_encoding(sock_DNS1,NULL,NULL);
	
	g_io_add_watch(sock_DNS1, G_IO_IN, (GIOFunc) handle_output,NULL);

	/* initialize the firewall */
	
	if (!g_file_test("/tmp/sicat.tmp",G_FILE_TEST_EXISTS)) {
	
		g_debug("initializing firewall");
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
	
	table = g_new0(gchar,10);
	strcpy(table,"0");
	
	g_timeout_add( ((CONFd("LoginTimeout")*1000) + 60000), (GSourceFunc) change_table, NULL );
	g_timeout_add( 1000, (GSourceFunc) check_exit_signal, loop );
    
	/* Go! */
	g_message("main: starting main loop");
	//g_main_run( loop );
	g_main_loop_run(loop);
	g_message("main: exiting main loop");
	
	return 0;
}
