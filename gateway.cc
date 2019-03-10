# include <glib.h>
# include <string.h>
# include <unistd.h>
# include <time.h>
# include "gateway.h"

GHashTable* peer_tab; 
unsigned long int total_connections = 0;
time_t last_connection = 0;
extern class comm_interface* wsk_comm_interface;

gchar* target_redirect(http_request *h){
	
    gchar *orig, *host   = HEADER("Host"); 
    
    if ( host != NULL ) {
		orig = g_strdup_printf( "http://%s%s", host, h->uri_orig );
    } else {
		orig = CONF("HomePage");
    }

    return orig;
}


gchar* local_host( http_request *h ) {
	
	gchar* ret = NULL;
	
	ret = g_strdup_printf( "%s:%s", h->sock_ip, CONF("GatewayPort") );
	
	return ret;
}

/************* Permit and deny peers *************/

peer* find_peer ( http_request *h) {
	
    peer* p; 
    
    p = (peer*) g_hash_table_lookup(peer_tab, h->hw);
    
    if (p == NULL) {
		p = peer_new(nocat_conf, h);
		g_hash_table_insert(peer_tab, (gpointer) p->hw, p);
		
    }
    return p;
}

/*void accept_peer ( http_request *h ) {
	
    peer *p;
	
	if (*(h->peer_ip) != 0) p  = find_peer( h->peer_ip);
	else p  = find_peer( h->peer_ip6);
    g_message( "accept_peer: Accepting peer %s", p->ip );

    total_connections++;
    time(&last_connection);

    peer_permit( nocat_conf, p,NULL);
}*/

/*void remove_peer ( peer *p ) {
	
    g_message( "remove_peer: Removing peer %s", p->ip );
    peer_deny(nocat_conf, p);
}*/

/*gboolean check_peer_expire ( gchar *ip, peer *p, time_t *now ) {
	
	if ((p->status == 0) || (p->status == 2)){
    	g_message("check_peer_expire: Checking peer %s for expire: %ld sec. remain",ip, p->expire - *now );
    	if (p->expire <= *now) {
			remove_peer(p);
			return TRUE;
    	}
    	else {
			return FALSE;
    	}
	}
	else return FALSE;
}*/

void compare_token( gchar *hw, peer *p, struct mi_struct* fr){
	
	if (!fr->encontrado){
		if (strcmp(p->token,fr->trama->parameters->items[1]->valor) == 0){
			
			fr->encontrado = TRUE;			
			if (strcmp(fr->trama->parameters->items[0]->valor,"true") == 0){
				
				g_debug("compare_token: peer %s autenticado, permitiendolo por todo el timeout...",hw);
				peer_permit(nocat_conf, p,NULL);
					
			}
		}
	}
}

gboolean check_peer(class m_frame* frame){
	
	mi_struct* fr = new struct mi_struct;
	fr->encontrado = FALSE;
	fr->trama = frame;
	
	g_hash_table_foreach(peer_tab,(GHFunc)compare_token,fr);
	wsk_comm_interface->reception_queu->delete_frame(frame->get_index());
	
	return FALSE;
}
