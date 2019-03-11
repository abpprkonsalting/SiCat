# include <glib.h>
# include <stdio.h>
# include <unistd.h>
# include <string.h>
# include <sys/types.h>
# include <sys/wait.h>
# include <string.h>
# include <errno.h>
# include <time.h>
# include <libwebsockets.h>
//# include "firewall.h"
# include "gateway.h"
//# include "websck.h"

extern class h_requests* requests;
extern char **environ;
extern gchar* macAddressFrom;
extern class comm_interface* wsk_comm_interface;
extern GHashTable* peer_tab;
extern gchar* table;

typedef struct {
    pid_t pid;
    peer *p;
    http_request *h;
} fw_action;

static void fw_exec_add_env(gchar *key, gchar *val, GPtrArray *env ) {
    gchar *p;
    
    p = g_strdup_printf( "%s=%s", key, val );
    g_ptr_array_add( env, p );
}

gboolean redirecciona_delayed (fw_action *act ){
	
	gchar* redir = (gchar*)g_hash_table_lookup(act->h->query,"redirect");
	GHashTable* args = g_hash_new();
	GString* dest;

	g_hash_set( args, "redirect",	redir );
	g_hash_set( args, "usertoken",	get_peer_token(act->p) );
	g_hash_set( args, "userMac",    act->p->hw );
	g_hash_set( args, "deviceMac",	macAddressFrom);

	dest = build_url( CONF("AuthServiceURL"), args );

	if (CONFd("usewsk")) wsk_comm_interface->wsk_restart();
	
	// Aquí debo buscar un mecanismo que espere porque el websocket esté establecido antes de mandarle
	// el redirect al usuario. Mientras se espera porque el websocket esté establecido se enviará una
	// página de espera al usuario. Este mecanísmo llevará un time-out, el cual cuando esté cumplido
	// le mostrará una página del error al usuario informándole que hay un error en la conexion con el
	// servidor del sistema y por lo tanto debe avisar a la administración del sistema para resolverlo
	// etc..
	
	http_send_redirect(act->h, dest->str,act->p);
	
	//g_debug("redirecciona_delayed: enviado el redirect");

	g_string_free( dest, 1 );
	g_hash_free( args );
	
    // Tengo que experimentar aquí poner g_source_unref(source) antes del g_source_destroy.
    
    GSource *source = g_main_context_find_source_by_id(NULL,act->h->source_id);
    g_source_destroy(source);
    g_io_channel_shutdown(act->h->channel,TRUE,NULL);
	g_io_channel_unref(act->h->channel );
	
	/*g_source_unref(source);
	gboolean destr = g_source_is_destroyed(source);
	if (destr == FALSE) {
		g_debug("destruyendo yo");
		
	}*/
	
	http_request_free(act->h);
	
	g_spawn_close_pid(act->pid);
	g_free(act);
	
	return FALSE;
}

void redirecciona(GPid pid,gint status,fw_action* act){
	
	if (act->h != NULL)	g_timeout_add(5000, (GSourceFunc) redirecciona_delayed, act);
	else {
		
		g_spawn_close_pid(act->pid);
		g_free(act);
	}
		
}

int fw_perform(gchar* action,GHashTable* conf,peer* p, http_request* h) {
	
    GHashTable *data;
    GPtrArray *env;
    gchar *cmd, **arg, **n, *tempo;
    GError* gerror = NULL;
    int resultado = 0;
    
    fw_action* act = g_new0( fw_action, 1 );

    if (p != NULL) act->p = p;
    if (h != NULL) act->h = h;
    
	data = g_hash_dup(conf);
    
    // Then add specifics about this particular client, if any
    if (p != NULL) {

		g_hash_set( data, "IP",p->ip );
		g_hash_set( data, "MAC",p->hw );
		g_hash_set( data, (gchar*)"Class", (gchar*)"Public" );
		//g_message(p->start_time);
		//g_message(p->end_time);
		g_hash_set( data, (gchar*)"Start", p->start_time );
		g_hash_set( data, (gchar*)"End", p->end_time );
		g_hash_set( data, "Table",table);
    }
    else if (strcmp(action,"InitCmd") == 0){
		
		g_hash_set( data, "Table",table);
		
	}
    
    cmd = conf_string(data,action);
    cmd = parse_template(cmd, data);

    arg = g_strsplit( cmd," ",0);

    // prime the environment with our existing environment
    env = g_ptr_array_new();
    for ( n = environ; *n != NULL; n++ ){
    	
    	tempo = g_strdup(*n);
    	g_ptr_array_add(env, tempo);
	}

    // Then add everything from the conf file
    g_hash_table_foreach( data, (GHFunc) fw_exec_add_env, env );

    // Add a closing NULL so execve knows where to lay off.
    g_ptr_array_add( env, NULL );
    
    if (g_spawn_async(NULL,arg,(char **)env->pdata,(GSpawnFlags)(G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_LEAVE_DESCRIPTORS_OPEN),
    							NULL,NULL,&(act->pid),&gerror))
    
    			g_child_watch_add(act->pid, (GChildWatchFunc)redirecciona,act);
    			
    else {
    	
    	if (gerror != NULL) {
				
			g_message("fw_perform: g_spawn_async failure, return error: %s",gerror->message);
		}
		else {
			
			g_message("fw_perform: g_spawn_async failure, unknown return error");
		}
		resultado = 1;
    }
    
    /************** Limpieza ******************/
    
    g_hash_free(data);
    g_ptr_array_free(env,TRUE);
    g_free(cmd);
    g_strfreev(arg);
     
    return resultado;
}

int fw_init ( GHashTable *conf ) {
	
    fw_perform( (gchar*)"ResetCmd", conf, NULL,NULL);
    
    if (CONFd("IPv6")) fw_perform( (gchar*)"ResetCmd6", conf, NULL,NULL);
    
    return 0;
}

int fw_resettable (GHashTable *conf) {
	
	fw_perform( (gchar*)"InitCmd", conf, NULL,NULL);
    
    return 0;
}

/******* peer.c routines **********/
/*void peer_extend_timeout( GHashTable *conf, peer *p, time_t ext ) {
    //p->expire = time(NULL) + conf_int( conf, "LoginTimeout" );
    p->expire = time(NULL) + ext;
}*/

peer* peer_new ( GHashTable* conf, http_request *h ) {
	
    peer* p = g_new0( peer, 1 );

    // Set IP
    strncpy( p->ip, h->peer_ip, sizeof(p->ip) );
    
    // Set MAC address.
    strncpy( p->hw, h->hw, sizeof(p->hw) );
    
    // Set connection time.
    p->current_time = time(NULL);
    p->s_time = time(NULL);
    p->e_time = time(NULL);
    p->start_time = g_new0(gchar,100);
    p->end_time = g_new0(gchar,100);
    p->token[0] = '\0';
    p->status = 0;
    p->contador_b = 0;
	p->contador_m = 0;
	
	p->p_uri_orig = g_strdup(h->uri_orig);
    
    return p;
}

void peer_free ( peer *p ) {

    g_free(p->start_time);
    g_free(p->end_time);
    g_free(p->p_uri_orig);
    g_free(p);
}

int peer_permit(GHashTable *conf, peer *p, http_request* h) {
    
	struct tm *loctime;
	
	p->current_time = time(NULL);
	
	p->s_time = time(NULL);
	loctime = localtime (&p->s_time);
	
	strftime (p->start_time, 100, "%H:%M:%S", loctime);
	
	if (h != NULL) p->e_time = p->s_time + CONFd("LoginGrace");
	else p->e_time = p->s_time + CONFd("LoginTimeout");
	
	loctime = localtime (&p->e_time);
	strftime (p->end_time, 100, "%H:%M:%S", loctime);
	
	if (h != NULL) {
		if (!(fw_perform( (gchar*)"Permit_t", conf, p,h) == 0)) return -1;
	}
	else {
		
		if (!(fw_perform( (gchar*)"PermitCmd", conf, p,h) == 0)) return -1;
	
		p->status = 3;
		p->current_time = time(NULL);
	}
	/*if (!(fw_perform( (gchar*)"PermitCmd", conf, p,h) == 0)) return -1;

	if (h == NULL){
		if (g_hash_table_remove(peer_tab,p->hw)) {
			g_debug("peer_permit: removido el peer de la hashtable");
			peer_free(p);
		}
	}*/

    return 0;
}

/*int peer_deny ( GHashTable *conf, peer *p ) {
	
    //g_assert( p != NULL );
    //g_message("peer status = %d",p->status);
    if (p->status != 1 ) {
    	
		if (fw_perform((gchar*)"DenyCmd", conf, p,NULL) == 0) {
				
				peer_free(p);
				//p->status = 1;
		} else {
				return -1;
		}
    }
    //g_message("peer status = %d",p->status);
    return 0;
}*/

//# ifdef HAVE_LIBCRYPT

gchar* get_peer_token ( peer *p ) {
    char *n;
    int carry = 1;
    
    if (strcmp(p->token,(char*)"\0") == 0){	// Esto está aquí porque si el token
    										// ya tiene un valor no es necesario
    										// volver a calcularlo, simplemente se devuelve.
    
		int len = sizeof(p->token) - 1;
		
		if (! *(p->token))	strrand(p->token, len);	

		for (n = p->token + len - 1; carry && n >= p->token; n--)
		switch (*n) {
			case '9': *n = '0'; carry = 1; break;
			case 'Z': *n = 'A'; carry = 1; break;
			case 'z': *n = 'a'; carry = 1; break;
			default : (*n)++; carry = 0;
		}
			
		n = md5_crypt( p->token, p->token + len - 8 );
		strncpy( p->token, n, len );
		p->token[len - 1] = '\0';

		g_free(n);
	}
    return p->token;
}



//# endif /* HAVE_LIBCRYPT */
