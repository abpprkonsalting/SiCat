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

//extern class h_requests* requests;
extern class comm_interface* wsk_comm_interface;
extern GHashTable* peer_tab;
extern gchar* macAddressFrom;
extern class DNS_resolver* resolver;
extern struct hs_array_t* hs_array;
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

/*void peer_init_dns_callback (GObject *source_object,GAsyncResult *res,gpointer user_data){
	
	GList *mylist;
	GError* gerror = NULL;
	
	mylist = g_resolver_lookup_by_name_finish((GResolver *)source_object,res,&gerror);
	
	if (gerror != NULL) {
				
		g_warning("peer_init_dns_callback: g_resolver_lookup_by_name_finish error: %s",gerror->message);

		return;
	}
	
	if (mylist != NULL){
		
		// Aqu'i debo agregar las direcciones ip que vengan en la respuesta dns a la tabla de sitios del peer.
		// Ahora no lo hago pues esto no es extrictamente necesario, pero m'as adelante ser'ia buena idea hacerlo.
		
		//(otro_struct*)(user_data)->solved_sites++;
		otro_struct *res_data = (otro_struct*)user_data;
		g_debug("lleg'o una respuesta dns del peer");
		//res_data->solved_sites++;
	}
	else g_warning("peer_init_dns_callback: g_resolver_lookup_by_name_finish error ..");
	return;
}*/

/*void peer_init_dns_callback (GObject *source_object,GAsyncResult *res,gpointer user_data){
	
	GList *mylist;
	GError* gerror = NULL;
	
	mylist = g_resolver_lookup_by_name_finish((GResolver *)source_object,res,&gerror);
	
	if (gerror != NULL) {
				
		g_warning("peer_init_dns_callback: g_resolver_lookup_by_name_finish error: %s",gerror->message);

		return;
	}
	
	if (mylist != NULL){
		
		g_debug("lleg'o una respuesta dns del peer");
		//res_data->solved_sites++;
	}
	else g_warning("peer_init_dns_callback: g_resolver_lookup_by_name_finish error ..");
	return;
}*/

void refill_site_table(struct respuesta* resp,void* user_data){

	/* A esta funci'on se le est'a entrando con una estructura respuesta que tiene tres campos:
	
	resp->pregunta :		Este es el nombre original del sitio sobre el cual se hizo la solicitud.
	resp->ip_addresses :	Arreglo de direcciones ip que llegaron en la respuesta. Aqu'i no me interesan.
	resp->nombres :			Arreglo de nombres y aliases del sitio. Esto es lo que me interesa agregar a la tabla.
	* 
	
	Tambi'en se le entra con la estructura "otro" original
	
	*/
	
	g_debug("refill_site_table: entering..");
	g_debug("pregunta: %s",(gchar*)resp->pregunta);
	otro_struct* otro = (otro_struct*) user_data;
	
	int a = 0;
	int i;
	unsigned char **tmp;
	uint32_t** temp_addresses;
	gboolean encontrado = FALSE;
	
	otro->solved_sites++;	// Este sitio ya est'a resuelto.
	
	// Buscar en la tabla de sitios del peer el sitio para el que se pregunt'o
	
	while ((otro->p->tabla_sitios[a] != NULL) && (encontrado == FALSE)) {
		
		//g_debug("analizing site %s",otro->p->tabla_sitios[a]->names[0]);
		
		if (strcmp((gchar*)otro->p->tabla_sitios[a]->names[0],(gchar*)resp->pregunta) == 0) {
			
			// Este es el sitio para el que se pregunt'o, por lo tanto lo que hay que hacer es agregar los nombres que vienen en la
			// respuesta a la lista de nombres del sitio en la tabla, as'i como agregar las direcciones ip tambi'en
			
			encontrado = TRUE;
			
			for (unsigned char** mm = &(resp->nombres[0]); *mm != NULL;mm++) {
				
				//g_debug("analizando respuesta %s",(*mm));
				
				//Recorrer la tabla a ver si esa respuesta ya est'a guardada.
				
				i = 0;
				while (otro->p->tabla_sitios[a]->names[i] != NULL){
						
					if (strcmp((const char*)otro->p->tabla_sitios[a]->names[i],(const char*)(*mm)) == 0){
					
						//g_debug("ese nombre de sitio ya est'a en la tabla");
						break;
					}
					i++;
				}
				
				if (otro->p->tabla_sitios[a]->names[i] == NULL) {
					
					tmp = g_new0(unsigned char*,i+2);
					memcpy(tmp,otro->p->tabla_sitios[a]->names,i*sizeof(unsigned char*));
					/*for (unsigned int k=0;k<i;k++) {
						tmp[k] = p->tabla_sitios[a]->names[k];
						g_debug("movido %s",tmp[k]);
					}*/
					g_free(otro->p->tabla_sitios[a]->names);
					otro->p->tabla_sitios[a]->names = tmp;
					otro->p->tabla_sitios[a]->names[i] = (unsigned char*)g_strdup((const char*)(*mm));
					g_debug("agregado el sitio %s a la tabla del peer",otro->p->tabla_sitios[a]->names[i]);
				}
			}
			
			for (sockaddr_in** mm = &(resp->ip_addresses[0]); *mm != NULL;mm++) {
				
				i = 0;
				while (otro->p->tabla_sitios[a]->ip_v4[i] != NULL){
						
					if (*(otro->p->tabla_sitios[a]->ip_v4[i]) == (*mm)->sin_addr.s_addr){
					
						//g_debug("esa ip ya est'a en la tabla");
						break;
					}
					i++;
				}
				//g_debug("1");
				if (otro->p->tabla_sitios[a]->ip_v4[i] == NULL) {
					
					long p1;
					struct sockaddr_in aa;
					p1=(*mm)->sin_addr.s_addr;
					//aa.sin_addr.s_addr=(*p1);

					temp_addresses = g_new0(uint32_t*,i+2);
					memcpy(temp_addresses,otro->p->tabla_sitios[a]->ip_v4,i*sizeof(uint32_t*));
					
					g_free(otro->p->tabla_sitios[a]->ip_v4);
					otro->p->tabla_sitios[a]->ip_v4 = temp_addresses;
					
					otro->p->tabla_sitios[a]->ip_v4[i] = g_new0(uint32_t,1);
					memcpy(otro->p->tabla_sitios[a]->ip_v4[i],&p1,sizeof(uint32_t));
					
					/*uint32_t** temp_addresses = g_new0(uint32_t*,otro->p->tabla_sitios[a]->ip_v4_addresses + 1 );
					
					for (unsigned int l=0;l < otro->p->tabla_sitios[a]->ip_v4_addresses;l++) temp_addresses[l] = otro->p->tabla_sitios[a]->ip_v4[l];
					
					g_free(otro->p->tabla_sitios[a]->ip_v4);

					otro->p->tabla_sitios[a]->ip_v4 = temp_addresses;
					
					otro->p->tabla_sitios[a]->ip_v4[otro->p->tabla_sitios[a]->ip_v4_addresses] = g_new0(uint32_t,1);
					
					otro->p->tabla_sitios[a]->ip_v4_addresses++;
					
					memcpy(otro->p->tabla_sitios[a]->ip_v4[otro->p->tabla_sitios[a]->ip_v4_addresses - 1],&p1,sizeof(uint32_t));*/
					
					aa.sin_addr.s_addr=(*otro->p->tabla_sitios[a]->ip_v4[i]);
					
					g_debug("agregada la ip # %d del sitio %s = %s",otro->p->tabla_sitios[a]->ip_v4_addresses,
							otro->p->tabla_sitios[a]->names[0],inet_ntoa(aa.sin_addr));
							
					otro->p->tabla_sitios[a]->ip_v4_addresses++;
					
				}
			}	
		}
		a++;
	}
	return;
}

gboolean get_rid_sombies_delayed (otro_struct* otro) {
	
	if (hs_array->locked == TRUE) return TRUE;
	else {
		
		hs_array->locked = TRUE;
			
		get_rid_sombies (otro->p);
		
		hs_array->locked = FALSE;
	
		http_send_redirect(otro->h, otro->dest->str);
		g_string_free( otro->dest, 1 );
		
		g_io_channel_shutdown(otro->h->sock,TRUE,NULL);
		g_io_channel_unref(otro->h->sock );
		remove_from_h_array(otro->h);
		
		g_free(otro);
	}
	return FALSE;
	
}

gboolean wait_wsk_solve_dns (otro_struct* otro) {
	
	if (otro->counter == 0){
		
		// Solicitar resoluci'on dns asincr'onica para cada una de las direcciones de la tabla del peer.
		unsigned int i = 0;
		while (otro->p->tabla_sitios[i] != NULL) {	// Esto se hace para cada sitio de la tabla
			
			//g_debug("resolviendo aliases y direcciones del sitio: %s",otro->p->tabla_sitios[i]->names[0]);
			resolver->solve_address((unsigned char*)otro->p->tabla_sitios[i]->names[0],T_A,refill_site_table,(otro_struct*) otro);
			i++;
		}	
	}
	else if (otro->counter/2 == (unsigned int)CONFd("wsk_dns_timeout")) {
		
		// Esto es la condici'on de timeout esperando por el wsk o por el dns, por lo tanto no se puede enviar el redirect al cliente
		// ,se env'ia entonces un redirect a una p'agina de error local que le informa del error al cliente y que contacte a la administraci'on
		// del sistema, etc..
		
		g_debug("wait_wsk_solve_dns: time out waiting for wsk or dns..");
		
		g_string_free( otro->dest, 1 );
		
		/*if (g_hash_table_remove(peer_tab,otro->p->hw)) {
			g_debug("wait_wsk_solve_dns: removido el peer de la hashtable");
			peer_free(otro->p);
		}*/
		
		g_io_channel_shutdown(otro->h->sock,FALSE,NULL);
		g_io_channel_unref(otro->h->sock );
		remove_from_h_array(otro->h);
		g_free(otro);	
		
		return FALSE;
	}
	else if (otro->solved_sites == otro->p->cantidad_sitios){
		
		if (CONFd("usewsk")) {
			
			if (wsk_comm_interface->get_status() != WSK_CLIENT_ESTABLISHED) {
				
				otro->counter++;
				return TRUE;
			}
		}
		
		// Hacer la redirecci'on aqu'i.
		
		otro->p->ready = TRUE;
		
		
		if (hs_array->locked == FALSE) {
			
			hs_array->locked = TRUE;
			
			get_rid_sombies (otro->p);
			
			hs_array->locked = FALSE;
		
			http_send_redirect(otro->h, otro->dest->str);
			g_string_free( otro->dest, 1 );
			
			g_io_channel_shutdown(otro->h->sock,TRUE,NULL);
			g_io_channel_unref(otro->h->sock );
			remove_from_h_array(otro->h);
			
			g_free(otro);
			
			return FALSE;
		}
		else {
			
			g_timeout_add(50,(GSourceFunc)get_rid_sombies_delayed, otro);
			return FALSE;
		}
	}
	otro->counter++;
	return TRUE;
}

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
	
	otro_struct* otro = g_new0( otro_struct, 1);
	otro->h = h;
	otro->p = p;
	otro->dest = dest;
	otro->counter = 0;
	otro->solved_sites = 0;
	
	g_timeout_add(100,(GSourceFunc)wait_wsk_solve_dns, otro);
	
	g_hash_free( args );
	//g_free( orig  );
	g_free( redir );
	
	return;    
}

int handle_request( http_request *h ) {
	
	peer* p;
	//gchar* peer_hw;
	int ret = 1;
	
	//g_debug("handle_request: entering..");
	
	p = find_peer(h);
		
	gchar *hostname = HEADER("Host");
	gchar *sockname = local_host(h);

	if (hostname == NULL || strcmp( hostname, sockname ) != 0) {

		capture_peer(h,p);
		ret = 0;
	}

	g_free(sockname);

	//g_debug("handle_request: leaving..");
    return ret;
}

/*void splash_peer ( http_request *h ) {
	
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
}*/

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
