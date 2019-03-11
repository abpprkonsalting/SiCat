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
		
		orig = g_strdup_printf("http://%s",CONF("HomePage"));
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

gboolean check_peer_expire (gchar *hw, peer *p, time_t *now ) {
	
	long int elapsed;
	long int login;
	long int grace;
	
	//g_debug("check_peer_expire: checking peer %s",hw);
	
	elapsed = (long int)(*now - p->current_time);
	login = (long int)CONFd("LoginTimeout");
	grace = (long int)CONFd("LoginGrace");
	
	//g_debug("elapsed: %d",elapsed);
	//g_debug("loginTimeout: %d",login);
	//g_debug("loginGrace: %d",grace);
	
	if (elapsed > (2 *login )) {	// Este es un peer que lleva mucho tiempo sin tr'afico, por lo tanto lo tumbamos.
		
		g_debug("check_peer_expire: el peer %s lleva mucho tiempo sin generar tr'afico, se elimina",hw);
		peer_free(p);
		return TRUE;
	}
	else {
		
		if ((p->status == 3) && (elapsed == login - 5)) {	// El peer est'a navegando pero se le est'a acabando el tiempo, por lo tanto
															// se pone en status 0 para que se vuelva a capturar en cuanto la regla de iptables
															// se le agote.
			p->status = 0;
		}
		else if (p->status == 2){	// El peer ya est'a en el tiempo de grace
		
			if ((*now - p->s_time) > CONFd("LoginGrace") - 5) {	// Se est'a llegando al final del grace period adicionar
																// m'as tiempo.
			
				//g_debug("check_peer_expire: se est'a llegando al final del logingrace para el peer %s, se le da m'as tiempo",hw);
				
				struct tm *loctime;
		
				p->s_time = time(NULL);
				loctime = localtime (&p->s_time);
				
				strftime (p->start_time, 100, "%H:%M:%S", loctime);
				
				p->e_time = p->s_time + CONFd("LoginGrace");
				
				loctime = localtime (&p->e_time);
				strftime (p->end_time, 100, "%H:%M:%S", loctime);
				
				fw_perform((gchar*)"Permit_t",nocat_conf, p,NULL);
			}
			
			if (elapsed > CONFd("LoginGrace")) {	// Ha pasado el login grace y el cliente hace rato que no va a datalnet
				
				//g_debug("contador_m: %u",p->contador_m);
				//g_debug("50 * contador_b: %u",50 * p->contador_b);
				
				if (p->contador_m > (50 * p->contador_b)) { // Si el tr'afico a otros sitios es mucho mayor que el tr'afico a datalnet
				
					g_debug("check_peer_expire: el peer %s ha generando mucho tr'afico fuera de datalnet, se castiga..",hw);
					p->status = 1;
					p->punish_time = time(NULL);
				}
			}
		}
		else if (p->status == 1){
			
			// El peer est'a castigado, contar el tiempo para quitarle el castigo.
			int castigo = CONFd("LoginPunish");
			
			if (castigo < 2 * CONFd("LoginGrace")) castigo = 2 * CONFd("LoginGrace");
			
			if ( (*now - p->punish_time) > castigo ) {
				
				// Ya pas'o el castigo
				
				g_debug("check_peer_expire: pas'o el tiempo de castigo, se quita");
				p->status = 0;
				
				p->current_time = time(NULL);
			    p->s_time = time(NULL);
			    p->e_time = time(NULL);
										
				p->contador_b = 0;
				p->contador_m = 0;
			} 
		}
	}
	return FALSE;
}

void compare_token( gchar *hw, peer *p, struct mi_struct* fr){
	
	if (!fr->encontrado){
		if (strcmp(p->token,fr->trama->parameters->items[1]->valor) == 0){
			
			fr->encontrado = TRUE;			
			if (strcmp(fr->trama->parameters->items[0]->valor,"true") == 0){
				
				g_debug("compare_token: peer %s autenticado, permitiendolo por todo el timeout...",hw);
				peer_permit(nocat_conf,p,NULL);
					
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
