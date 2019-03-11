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
extern class comm_interface* wsk_comm_interface;
extern GHashTable* peer_tab;
extern gchar* macAddressFrom;
//gchar *splash_page = NULL;

gboolean finish_punishment(peer* p){
	
	g_debug("quitando el castigo al peer %s", p->hw);
	//p->status = 0;
	g_debug("castigo quitado");
	return FALSE;
}

/*
gboolean check_peer_grace_finish(gchar* p_hw){
	
	peer* p; 
    
    p = (peer*) g_hash_table_lookup(peer_tab, p_hw);
    
    if (p != NULL){	// Esto significa que el peer a'un no se ha autenticado en el sistema, pues de haberlo hecho se hubiera
					// quitado de la hashtable de peers en firewall.cc -> peer_permit
		
		g_debug("punishing peer %s", p->hw);
		//p->status = 1;
		p->punish_time = time(NULL);
		g_timeout_add(CONFd("LoginPunish")*1000,(GSourceFunc) finish_punishment,p);
	}
	g_free(p_hw);
	return FALSE;
}
*/

void capture_peer ( http_request *h,peer* p ) {
	
    //gchar *dest;
    gchar *redir = target_redirect(h);
    //gchar *redir = url_encode(orig);
    GString* dest;
    
    GHashTable* args = g_hash_new();

	g_hash_set( args, "redirect",	redir );
	g_hash_set( args, "usertoken",	get_peer_token(p) );
	g_hash_set( args, "userMac",    p->hw );
	g_hash_set( args, "deviceMac",	macAddressFrom);

	dest = build_url( CONF("AuthServiceURL"), args );
	
	if (CONFd("usewsk")) wsk_comm_interface->wsk_restart();
	
	// Aquí debo buscar un mecanismo que espere porque el websocket esté establecido antes de mandarle
	// el redirect al usuario. Mientras se espera porque el websocket esté establecido se enviará una
	// página de espera al usuario. Este mecanísmo llevará un time-out, el cual cuando esté cumplido
	// le mostrará una página del error al usuario informándole que hay un error en la conexion con el
	// servidor del sistema y por lo tanto debe avisar a la administración del sistema para resolverlo
	// etc..
	
	http_send_redirect(h, dest->str);
	
	g_string_free( dest, 1 );
	g_hash_free( args );
	//g_free( orig  );
	g_free( redir );
	
	return;    
}

int handle_request( http_request *h ) {
	
	peer* p;
	gchar* peer_hw;
	
	//g_debug("handle_request: entering..");
	
	p = find_peer(h);
		
	gchar *hostname = HEADER("Host");
	gchar *sockname = local_host(h);

	if (hostname == NULL || strcmp( hostname, sockname ) != 0) {

		capture_peer(h,p);
	}

	g_free(sockname);

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

/*
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
*/
