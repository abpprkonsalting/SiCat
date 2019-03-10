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

void capture_peer ( http_request *h ) {
	
    gchar *dest, *orig = target_redirect(h);
    gchar *redir = url_encode(orig);

	if (*(h->sock_ip) != 0)
    	dest = g_strdup_printf( "http://%s:%s/?redirect=%s",h->sock_ip, CONF("GatewayPort"), redir ); 
    else dest = g_strdup_printf( "http://[%s]:%s/?redirect=%s",h->sock_ip6, CONF("GatewayPort"), redir ); 

    http_send_redirect( h, dest, NULL );

    //g_message( "Captured peer %s", h->peer_ip );
    
    //g_message( "dest: %s", dest);

    g_free( orig  );
    g_free( redir );
    g_free( dest  );
}

void logout_peer( http_request *h, peer *p ) {
	
    remove_peer( p );
    http_send_redirect( h, CONF("LogoutURL"), NULL );
}

int handle_request( http_request *h ) {
	
	peer* p;
	if (*(h->peer_ip) != 0)	p = find_peer(h->peer_ip);
	else p = find_peer(h->peer_ip6);
	
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
				//g_message("peer en proceso de autentificación, permitiendolo por el grace period...");
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

void splash_peer ( http_request *h ) {
	
    GHashTable *data1;
    gchar *path = NULL, *file, *action1, *host;
    GIOError r;
   
    host = local_host( h );
    action1 = g_strdup_printf("http://%s/", host);
    data1 = g_hash_dup( nocat_conf );
    g_hash_merge( data1, h->query );
    g_hash_set( data1, "action1", action1 );
	
	path = http_fix_path( CONF("SplashForm"), CONF("DocumentRoot") );
	file = load_file( path );
	
	if (file != NULL) {
		
		r = http_serve_template( h, file, data1 );
		//g_message( "Splashed peer %s", h->peer_ip );
	}

    g_hash_free( data1 );
    g_free( action1 );
    g_free( host );
    if ( path != NULL ) {
		g_free( file );
		g_free( path );
    }
}
