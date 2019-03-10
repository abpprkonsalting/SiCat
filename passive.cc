# include <glib.h>
# include <string.h>
# include <stdio.h>
# include <netinet/in.h>
# include <sys/socket.h>
# include <sys/types.h>
# include <sys/wait.h>
# include <unistd.h>
# include "gateway.h"
//# include "websck.h"

extern class h_requests* requests;
//gchar *splash_page = NULL;

/*struct redirect{
	
	http_request* h;
	GString* dest;
};*/

//extern class files_array* clients_fw_files_array;
//struct redirect* redire;

/*gboolean redirecciona( GIOChannel *channel, GIOCondition cond, struct redirect* redire){
	
	//http_send_redirect(redire->h, redire->dest->str);
	//g_string_free( redire->dest, 1 );
	
	//clients_fw_files_array->remove_chann(channel);
	g_message("yes");
	
	return TRUE;
}*/

/*void capture_peer ( http_request *h, peer *p ) {
	
	if (h->perm) {
		if (p->status != 2) {
			
			p->status = 2;
			h->perm = FALSE;
			g_message("peer en proceso de autentificación, permitiendolo por el grace period...");
			peer_permit (nocat_conf,p,h);
		}
	}
	else {
		
		/*char *dest = (char*)calloc(1,110);
		GIOError r;
    	int n;
		memcpy ((char*)dest,(const char *)"HTTP/1.1 303 See Other\r\nLocation: http://192.168.1.1/splash.html\r\n\r\n",74);
		r = g_io_channel_write(h->sock, dest, strlen(dest), (guint*)&n );
    	g_message("sent first header: %s",dest);
    	
		free(dest);
		
		gint fid = g_io_channel_unix_get_fd(h->sock);
		struct sockaddr_in remote_socket;	
		socklen_t n1 = sizeof(struct sockaddr_in);
		getpeername (fid, (struct sockaddr *)&remote_socket,  &n1 );
		g_message( "Captured peer %s:%d", h->peer_ip,remote_socket.sin_port );

		
		g_io_channel_shutdown(h->sock,FALSE,NULL);
		g_io_channel_unref(h->sock );
		requests->remove(h);
		
		splash_peer(h);
    }
}*/

void capture_peer ( http_request *h ) {
	
    gchar *dest, *orig = target_redirect(h);
    gchar *redir = url_encode(orig);

    dest   = g_strdup_printf( "http://%s:%s/?redirect=%s",
	h->sock_ip, CONF("GatewayPort"), redir ); 

    http_send_redirect( h, dest, NULL );

    g_message( "Captured peer %s", h->peer_ip );
    
    //g_message( "dest: %s", dest);

    g_free( orig  );
    g_free( redir );
    g_free( dest  );
}

void logout_peer( http_request *h, peer *p ) {
	
    remove_peer( p );
    http_send_redirect( h, CONF("LogoutURL"), NULL );
}

/*int handle_request( http_request* h ) {
	
    gchar* hostname = HEADER("Host");
    gchar* sockname = local_host(h);
    int returno;
    
    gboolean is_new = FALSE;
    
    if ((hostname == NULL) || (strcmp(hostname, sockname) != 0)) {
    	
    	peer* p = find_peer(h->peer_ip);
    	capture_peer(h,p);
    	returno = 0;
	}
	else returno = 1;
    
    g_free(sockname);
    return returno;
}*/

int handle_request( http_request *h ) {
	
	peer* p = find_peer(h->peer_ip);
	
    gchar *hostname = HEADER("Host");
    gchar *sockname = local_host(h);

    //g_assert( sockname != NULL );

    if (hostname == NULL || strcmp( hostname, sockname ) != 0) {

		capture_peer(h);
    }
    else if (strcmp( h->uri, "/" ) == 0) {

		if ( QUERY("mode_login") != NULL || QUERY("mode_login.x") != NULL ) {
			
			//accept_peer(h);
			//sleep(2);
			//http_send_redirect( h, QUERY("redirect"),NULL );
			
			if (p->status != 2) {
			
				p->status = 2;
				//h->perm = FALSE;
				g_message("peer en proceso de autentificación, permitiendolo por el grace period...");
				peer_permit (nocat_conf,p,h);
				g_free( sockname );
				return 0;
			}
			
			
		}
		else if ( QUERY("redirect") != NULL ) {
			
			splash_peer(h);
		} 
		else {
			
			capture_peer(h);
		}
    }
    /*else if (strcmp( h->uri, "/status" ) == 0) {
		status_page( h );
    }*/ 
    else {
		http_serve_file( h, CONF("DocumentRoot") );
    }

    g_free( sockname );
    return 1;
}

/*void splash_peer ( http_request *h ) {
	
    GHashTable *data1;
    gchar *path = NULL, *file, *action, *host;
    GIOError r;
   
	g_message( "entre en splash_peer");
    //host = local_host(h);
    //action = g_strdup_printf("http://%s/",host);
    
    action = g_strdup_printf("http://%s%s",HEADER("Host"),h->uri);
    
    g_message( "action: %s",action);
    
    data1 = g_hash_dup(nocat_conf);
    g_message( "voy por 1");
    //g_hash_merge( data1, h->query );
    g_message( "voy por 1.5");
    g_hash_set( data1, "action", action );
    g_message( "voy por 1.75");

    /*if (splash_page) {
		file = splash_page;
    } 
   	else {
		path = http_fix_path(CONF("SplashForm"), CONF("DocumentRoot"));
		file = load_file(path);
    }

	path = http_fix_path(CONF("SplashForm"), CONF("DocumentRoot"));
	
	g_message( "path: %s",path);
	
	file = load_file(path);
	
	g_message( "file: %s",file);
	
	g_message( "voy por 2");
	
    r = http_serve_template( h, file, data1 );
    if (r == G_IO_ERROR_NONE) g_message( "Splashed peer %s", h->peer_ip );

    g_hash_free( data1 );
    g_free( action );
    g_free( host );
    if ( path != NULL ) {
		g_free( file );
		g_free( path );
    }
}*/

void splash_peer ( http_request *h ) {
	
    GHashTable *data;
    gchar *path = NULL, *file, *action1, *host;
    GIOError r;
   
    host = local_host( h );
    action1 = g_strdup_printf("http://%s/", host);
    data = g_hash_dup( nocat_conf );
    g_hash_merge( data, h->query );
    g_hash_set( data, "action1", action1 );
	
	path = http_fix_path( CONF("SplashForm"), CONF("DocumentRoot") );
	file = load_file( path );
	
    r = http_serve_template( h, file, data );
    if (r == G_IO_ERROR_NONE)
	g_message( "Splashed peer %s", h->peer_ip );

    g_hash_free( data );
    g_free( action1 );
    g_free( host );
    if ( path != NULL ) {
	g_free( file );
	g_free( path );
    }
}
