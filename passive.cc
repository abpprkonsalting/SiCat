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
	
	return FALSE;
}

gboolean check_peer_grace_finish(gchar* p_hw){
	
	peer* p; 
    
    p = (peer*) g_hash_table_lookup(peer_tab, p_hw);
    
    if (p != NULL){	// Esto significa que el peer a'un no se ha autenticado en el sistema, pues de haberlo hecho se hubiera
					// quitado de la hashtable de peers en firewall.cc -> peer_permit
		
		g_debug("castigando al peer %s", p->hw);
		p->status = 1;
		p->punish_time = time(NULL);
		g_timeout_add(CONFd("LoginPunish")*1000,(GSourceFunc) finish_punishment,p);
	}
	g_free(p_hw);
	return FALSE;
}

void capture_peer (http_request *h, peer *p) {
	
    gchar *dest, *orig = target_redirect(h);
    gchar *redir = url_encode(orig);

	dest = g_strdup_printf( "http://%s:%s/?redirect=%s",CONF("GatewayAddr"), CONF("GatewayPort"), redir );

    http_send_redirect(h, dest, p);

    g_free( orig  );
    g_free( redir );
    g_free( dest  );
}

void return_peer (http_request *h, peer *p, gchar *hostname) {
	
    gchar *dest;

	dest = g_strdup_printf( "http://%s%s",hostname, h->uri_orig );

    http_send_redirect(h, dest, p);
    g_free( dest  );
}

gchar* arregla_redirect(gchar* t1){
	
	gchar *t3 = g_strstr_len(t1,-1,"%3A");
	*t3 = ':';
	t3++;
	gchar *t4 = t3;
	t4++;
	t4++;
	memmove(t3,t4,strlen(t4)+1);
	
	gchar *t5 = g_strstr_len(t3,-1,"%2F");
	
	while ( t5 != NULL) {
		
		*t5 = '/';
		t5++;
		t4 = t5;
		t4++;
		t4++;
		memmove(t5,t4,strlen(t4)+1);
		t5 = g_strstr_len(t5,-1,"%2F");
	}
	
	return t1;
	
}

/*void logout_peer( http_request *h, peer *p ) {
	
    remove_peer( p );
    http_send_redirect( h, CONF("LogoutURL"), NULL );
}*/

int handle_request( http_request *h ) {
	
	peer* p;
	gchar *hostname = HEADER("Host");
	gchar *sockname = local_host(h);
	gchar *t, *t1, *t2, *dest;
	
	//g_debug("handle_request: entering..");
	
	p = find_peer(h);
	//g_debug("handle_request: peer status = %d", p->status);
	
	switch (p->status){
		
		case 0:		// 0 = En proceso de autentificaci'on
			
			if (g_strstr_len(h->buffer->str,50,"/Account/ExternalLogin?userMac=") != NULL) {
							
				// Aqu'i se captur'o una solicitud atrasada a datalnet despue's de un castigo, por lo tanto se
				// redirecciona nuevamente al principio.
				
				g_debug("handle_request: capturada una solicitud atrasada");
				
				t = g_strdup(h->buffer->str);
				t1 = g_strstr_len(t,-1,"&redirect=");
		
				for (int i = 0; i<10;i++) t1++;
				t2 = g_strstr_len(t1,-1,"&deviceMac");
				*t2 = '\0';
				//g_debug("t1 before = %s",t1);
				
				arregla_redirect(t1);
				
				//g_debug("t1 after = %s",t1);
				
				dest = g_strdup_printf( "http://%s:%s/?redirect=%s",CONF("GatewayAddr"), CONF("GatewayPort"), t1 );
				
				http_send_redirect1( h, dest, NULL );
				g_free(t);
				g_free(dest);
		
			}
			else if (hostname == NULL || strcmp( hostname, sockname ) != 0) {
		
				capture_peer(h,p);
			}
			else if (strcmp( h->uri, "/" ) == 0) {
		
				if ( QUERY("mode_login") != NULL || QUERY("mode_login.x") != NULL ) {
					
					g_debug("handle_request: peer %s en proceso de autentificación, permitiendolo por el grace period...", h->peer_ip);
					
					// Aqu'i se abre el firewall por el grace period enviando los paquetes ip para modo de usuario, de tal manera 
					// que se empieza a contar el tr'afico bueno y el malo. El peer se pone en modo 2.
					
					peer_permit(nocat_conf,p,h);
					//g_debug("handle_request: peer %s en modo 2...", h->peer_ip);
					p->status = 2;
					p->current_time = time(NULL);
					p->contador_b = 0;
					p->contador_m = 0;
	
					g_free( sockname );
					return 0;
				}
				else if ( QUERY("redirect") != NULL ) {
					
					splash_peer(h);
				} 
				else {
					
					capture_peer(h,p);
				}
			}
			else {
				http_serve_file( h, CONF("DocumentRoot") );
			}
			break;
			
		case 1:		// 1 = Castigado.
			
			if ( (g_strstr_len(h->buffer->str,-1,"/Account/ExternalLogin?userMac=") != NULL) &&
				(g_strstr_len(h->buffer->str,-1,"&deviceMac=") != NULL) && (g_strstr_len(h->buffer->str,-1,"usertoken=") != NULL) ) {
					
				// Aqu'i el cliente est'a capturado y para salir del castigo oprime el bot'on de datalnet lo que har'ia que se redireccione
				// el POST a datalnet, lo que no puede ser, por lo tanto se le env'ia para el principio con la direcci'on original que quer'ia
				// abrir.
				
				g_debug("handle_request: capturada una solicitud atrasada");
				
				t = g_strdup(h->buffer->str);
				t1 = g_strstr_len(t,-1,"&redirect=");
		
				for (int i = 0; i<10;i++) t1++;
				t2 = g_strstr_len(t1,-1,"&deviceMac");
				*t2 = '\0';
				//g_debug("t1 before = %s",t1);
				
				arregla_redirect(t1);
				
				//g_debug("t1 after = %s",t1);
				
				punish_peer(h,p,t1);
				
				g_free(t);
			}
			else {
				if (g_strstr_len(h->uri_orig,-1,"/images/socialwifilogo.png") != NULL) {
					
				    int fd, status;
				    fd = http_open_file( "/usr/share/sicat/htdocs/images/socialwifilogo.png", &status );
				
				    http_add_header(  h, "Content-Type", http_mime_type("/usr/share/sicat/htdocs/images/socialwifilogo.png") );
				    http_add_header ( h, "Connection", "close");
				    http_send_header( h, status, fd == -1 ? "Not OK" : "OK", NULL );
				
				    if ( fd != -1 )
					http_sendfile( h, fd );
				
				    close(fd);
				}
				else punish_peer(h,p,NULL);
			}
			break;
		case 2:		// 2 = Navegando por el grace period.
			
			if (strcmp(hostname, sockname) != 0){	// El peer deber'ia estar saliendo a internet porque se le abri'o el firewall por el grace period
													//,por lo tanto esto es un sombie, se le redirecciona para que vuelva a salir correctamente.
					
				return_peer (h,p,hostname);	
			}	
			
			break;
		case 3:		// 3 = Navegando autorizado.
			
			if (strcmp( hostname, sockname ) != 0){	// El peer deber'ia estar saliendo a internet porque se le abri'o el firewall por el grace period
													//,por lo tanto esto es un sombie, se le redirecciona para que vuelva a salir correctamente.
					
				return_peer (h,p,hostname);	
			}
			
			break;
		
		default:
			
			break;
	}
	g_free( sockname );
	return 1;
	//g_debug("handle_request: leaving..");
    
}

void splash_peer ( http_request *h ) {
	
    GHashTable *data1;
    gchar *path = NULL, *file, *action1, *host;
    //GIOError r;
   
    host = local_host( h );
    action1 = g_strdup_printf("http://%s/", host);
    data1 = g_hash_dup( nocat_conf );
    g_hash_merge( data1, h->query );
    g_hash_set( data1, "action1", action1 );
	
	path = http_fix_path( CONF("SplashForm"), CONF("DocumentRoot") );
	file = load_file( path );
	
	if (file != NULL) {
		
		http_serve_template( h, file, data1 );
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

void punish_peer ( http_request *h,peer* p, gchar* original_url) {
	
    GHashTable *data1;
    gchar *path = NULL, *file, *action1, *host;
    //GIOError r;
    time_t actual_time;
    gchar* diff;
    
    if (original_url == NULL) action1 = target_redirect(h);
    else action1 = original_url;
   
    data1 = g_hash_dup(nocat_conf);
    
    actual_time = time(NULL) - p->punish_time;
    //g_debug("punish_peer: actual_time = %d",actual_time);
    //g_debug("punish_peer: se resta = %d",((unsigned int)CONFd("LoginPunish") - actual_time) + 5);
    diff = g_strdup_printf("%u",((unsigned int)CONFd("LoginPunish") - actual_time) + 5);
    
    g_hash_set( data1, "diff1", diff);
    g_hash_set( data1, "action1", action1 );

	path = http_fix_path(CONF("PunishForm"), CONF("DocumentRoot"));
	file = load_file(path);
	if (file != NULL) {
		
		http_serve_template(h, file, data1);
		g_debug( "punish_peer: peer %s informed of punishment", h->peer_ip );
	}
	
    g_hash_free( data1 );
    g_free(diff);
    if (original_url == NULL) g_free( action1 );
    //g_free( host );
    if ( path != NULL ) {
		g_free( file );
		g_free( path );
    }
}
