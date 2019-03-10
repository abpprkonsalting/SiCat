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
extern GHashTable* peer_tab;
//gchar *splash_page = NULL;

gboolean finish_punishment(peer* p){
	
	g_debug("quitando el castigo al peer %s", p->hw);
	p->status = 0;
	g_debug("castigo quitado");
	return FALSE;
}

gboolean check_peer_grace_finish(gchar* p_hw){
	
	peer* p; 
    
    p = (peer*) g_hash_table_lookup(peer_tab, p_hw);
    
    if (p != NULL){	// Esto significa que el peer a'un no se ha autenticado en el sistema, pues de haberlo hecho se hubiera
					// quitado de la hashtable de peers en firewall.cc -> peer_permit
		
		g_debug("punishing peer %s", p->hw);
		p->status = 1;
		p->punish_time = time(NULL);
		g_timeout_add(CONFd("LoginPunish")*1000,(GSourceFunc) finish_punishment,p);
	}
	g_free(p_hw);
	return FALSE;
}

void capture_peer ( http_request *h ) {
	
    gchar *dest, *orig = target_redirect(h);
    gchar *redir = url_encode(orig);

	if (*(h->sock_ip) != 0)
    	dest = g_strdup_printf( "http://%s:%s/?redirect=%s",h->sock_ip, CONF("GatewayPort"), redir ); 
    else dest = g_strdup_printf( "http://[%s]:%s/?redirect=%s",h->sock_ip6, CONF("GatewayPort"), redir ); 

    http_send_redirect( h, dest, NULL );

    g_free( orig  );
    g_free( redir );
    g_free( dest  );
}

/*void logout_peer( http_request *h, peer *p ) {
	
    remove_peer( p );
    http_send_redirect( h, CONF("LogoutURL"), NULL );
}*/

int handle_request( http_request *h ) {
	
	peer* p;
	gchar* peer_hw;
	
	//g_debug("handle_request: entering..");
	
	p = find_peer(h);
	//g_debug("handle_request: peer status = %d", p->status);
	
	if (p->status == 0){
		
		gchar *hostname = HEADER("Host");
		gchar *sockname = local_host(h);
	
		if (hostname == NULL || strcmp( hostname, sockname ) != 0) {
	
			capture_peer(h);
		}
		else if (strcmp( h->uri, "/" ) == 0) {
	
			if ( QUERY("mode_login") != NULL || QUERY("mode_login.x") != NULL ) {
				
				g_debug("handle_request: peer %s en proceso de autentificación, permitiendolo por el grace period...", h->peer_ip);
				
				peer_permit (nocat_conf,p,h);
				
				//g_debug("1");
				
				if (CONFd("AllowPunishment")){
					peer_hw = g_new0(gchar,20);
					strcpy(peer_hw,p->hw);
					g_timeout_add(CONFd("LoginGrace")*1000,(GSourceFunc) check_peer_grace_finish,peer_hw);
				}
				//g_debug("2");
				g_free( sockname );
				//g_debug("handle_request: leaving..");
				return 0;
				
				
			}
			else if ( QUERY("redirect") != NULL ) {
				
				splash_peer(h);
			} 
			else {
				
				capture_peer(h);
			}
		}
		else {
			http_serve_file( h, CONF("DocumentRoot") );
		}
		
		g_free(sockname);
	}
	else if (p->status == 1) {
		
		if (strcmp( h->uri, "/images/socialwifilogo.png" ) == 0) http_serve_file( h, CONF("DocumentRoot") );
		else punish_peer(h,p);
	}

	//g_debug("handle_request: leaving..");
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
		g_debug( "splash_peer: peer %s splashed", h->peer_ip );
	}

    g_hash_free( data1 );
    g_free( action1 );
    g_free( host );
    if ( path != NULL ) {
		g_free( file );
		g_free( path );
    }
}

void punish_peer ( http_request *h,peer* p ) {
	
    GHashTable *data1;
    gchar *path = NULL, *file, *action1, *host;
    GIOError r;
    time_t actual_time;
    gchar* diff;
    
    //host = local_host( h );
    //action1 = g_strdup_printf("http://%s/", host);
    
    action1 = target_redirect(h);
   
    data1 = g_hash_dup(nocat_conf);
    
    actual_time = time(NULL) - p->punish_time;
    diff = g_strdup_printf("%u",((unsigned int)CONFd("LoginPunish") - actual_time) + 5);
    
    g_hash_set( data1, "diff1", diff);
    g_hash_set( data1, "action1", action1 );

	path = http_fix_path(CONF("PunishForm"), CONF("DocumentRoot"));
	file = load_file(path);
	if (file != NULL) {
		
		r = http_serve_template(h, file, data1);
		g_debug( "punish_peer: peer %s informed of punishment", h->peer_ip );
	}
	
    g_hash_free( data1 );
    g_free(diff);
    g_free( action1 );
    //g_free( host );
    if ( path != NULL ) {
		g_free( file );
		g_free( path );
    }
}
