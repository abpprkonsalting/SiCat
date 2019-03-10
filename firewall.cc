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

typedef struct {
    pid_t pid;
    gchar *cmd;
    peer *p;
} fw_action;

typedef struct {
	http_request *h;
	peer *p;
} redi;

static void fw_exec_add_env ( gchar *key, gchar *val, GPtrArray *env ) {
    gchar *p;
    
    g_assert( key != NULL );
    g_assert( val != NULL );
    p = g_strdup_printf( "%s=%s", key, val );
    g_ptr_array_add( env, p );
}

static int fw_exec( fw_action *act, GHashTable *conf ) {
	
    GHashTable *data2;
    GPtrArray *env;
    gchar *cmd, **arg, **n;

	g_message("entré en fw_exec con action = %s",act->cmd);
    data2 = g_hash_dup(conf);
    
    //g_message("retorné de g_hash_dup");
    //
    // Than add specifics about this particular client, if any
    if (act->p != NULL) {
		//g_message("act->p existe");
		g_hash_set( data2, "IP",    act->p->ip );
		g_hash_set( data2, "MAC",   act->p->hw );
		g_hash_set( data2, (gchar*)"Class", (gchar*)"Public" );
    }
    /*else {
    	g_message("act->p no existe");
	}*/

    cmd = conf_string( data2, act->cmd ); /*****************/
    cmd = parse_template( cmd, data2 );
    g_message("Got command %s from action %s", cmd, act->cmd );
    arg = g_strsplit( cmd, " ", 0 );

    // prime the environment with our existing environment
    env = g_ptr_array_new();
    for ( n = environ; *n != NULL; n++ )	g_ptr_array_add( env, *n );

    // Then add everything from the conf file
    g_hash_table_foreach( data2, (GHFunc) fw_exec_add_env, env );

    // Add a closing NULL so execve knows where to lay off.
    g_ptr_array_add( env, NULL );

    /* We're not cleaning up memory references because 
     * hopefully the exec won't fail... */
    execve( *arg, arg, (char **)env->pdata );
    g_message( "execve %s failed: %m", cmd ); // Shouldn't happen.
    return -1;
}

gboolean fw_cleanup( fw_action *act ) {
	
    guint status = 0, retval = 0;
    pid_t r = 0;

    r = waitpid( act->pid, (int*)&status, WNOHANG );
    
    if (! r) {
	return TRUE;

    } else if (r == -1 && errno != EINTR) {
	g_warning( "waitpid failed: %m" );
	return TRUE;
	
    } else if (WIFEXITED(status)) {
	retval = WEXITSTATUS(status);
	if (retval)
	    g_warning( "%s on peer %s returned %d",
		    act->cmd, act->p->ip, retval );
	
    } else if (WIFSIGNALED(status)) {
	retval = WTERMSIG(status);
	g_warning( "%s of peer %s died from signal %d", 
		act->cmd, act->p->ip, retval );
    }


    g_free( act );
    return FALSE;
}

/*static void http_compose_header ( gchar *key, gchar *val, GString *buf ) {
    g_string_sprintfa( buf, "%s: %s\r\n", key, val );
}*/

gboolean redirecciona_delayed (redi* red){
	
	gchar* redir = (gchar*)g_hash_table_lookup(red->h->query,"redirect");
	GHashTable* args = g_hash_new();
	GString* dest;

	g_hash_set( args, "redirect",	redir );
	g_hash_set( args, "usertoken",	get_peer_token(red->p) );
	g_hash_set( args, "userMac",    red->p->hw );
	g_hash_set( args, "deviceMac",	macAddressFrom);

	dest = build_url( CONF("AuthServiceURL"), args );

	wsk_comm_interface->wsk_send_command(NULL,NULL,NULL);
	
	http_send_redirect(red->h, dest->str,red->p);

	g_string_free( dest, 1 );
	g_hash_free( args );
	//g_free( redir );
	
    g_io_channel_shutdown(red->h->sock,FALSE,NULL);
	g_io_channel_unref(red->h->sock );
	requests->remove(red->h);
	
	return FALSE;
}

void redirecciona(GPid pid,gint status,redi* red){
	
	g_timeout_add( 2000, (GSourceFunc) redirecciona_delayed, red);
}

int fw_perform(gchar* action,GHashTable* conf,peer* p, http_request* h) {
	
    fw_action* act = g_new( fw_action, 1 );
    redi* red = g_new( redi,1);
    pid_t pid;

    act->cmd = action;
    act->p = p;
    
    if (h != NULL) red->h = h;
    if (p != NULL) red->p = p;
    
	//g_message("antes del fork..");
    pid = fork();
    if (pid == -1){	
    	//g_message( "Can't fork: %m" );
    	lwsl_info("Can't fork: %m");
    }
    
    if ((h != NULL) && (pid > 0)) {
    	 	
    	 //g_message("añadiendo el watch");
    	 g_child_watch_add (pid, (GChildWatchFunc)redirecciona,red);
    	 //g_message("añadido el watch");
	}
    
    if (!pid) {
    	
    	//sleep(1);
    	//g_message("ejecutando el fw_exec");
    	fw_exec(act, conf);
	}

    //act->pid  = pid;
    //g_idle_add( (GSourceFunc) fw_cleanup, act );
    return 0;
}

int fw_init ( GHashTable *conf ) {
	
    return fw_perform( (gchar*)"ResetCmd", conf, NULL,NULL);
}

/******* peer.c routines **********/
void peer_extend_timeout( GHashTable *conf, peer *p, time_t ext ) {
    //p->expire = time(NULL) + conf_int( conf, "LoginTimeout" );
    p->expire = time(NULL) + ext;
}

peer* peer_new ( GHashTable* conf, const gchar *ip ) {
	
    peer* p = g_new0( peer, 1 );
    //g_assert( p != NULL );
    //g_assert( ip != NULL );
    // Set IP address.
    strncpy( p->ip, ip, sizeof(p->ip) );
    // Set MAC address.
    peer_arp( p );
    // Set connection time.
    p->connected = time( NULL );
    p->token[0] = '\0';
    p->status = 1;
    peer_extend_timeout(conf, p,conf_int( conf, "LoginGrace" ));
    
    p->first_redirect = g_string_new("");
    
    return p;
}

void peer_free ( peer *p ) {
    g_assert( p != NULL );
    if (p->request != NULL) g_free( p->request );
    g_string_free(p->first_redirect,TRUE);
    g_free(p);
}

int peer_permit ( GHashTable *conf, peer *p, http_request* h) {
    
    time_t extension = 0;
    //g_message("peer status = %d",p->status);
    if (p->status == 2) {
    	
    	if (!(fw_perform( (gchar*)"PermitCmd", conf, p,h) == 0)) return -1;
    	
    	extension = conf_int( conf, "LoginGrace" );
	}
	else if (p->status == 0){
		
		if (!(fw_perform( (gchar*)"PermitCmd", conf, p,NULL) == 0)) return -1;
		
		extension = conf_int( conf, "LoginTimeout" );
	}
	
	peer_extend_timeout(conf, p, extension);
    return 0;
}

int peer_deny ( GHashTable *conf, peer *p ) {
	
    //g_assert( p != NULL );
    //g_message("peer status = %d",p->status);
    if (p->status != 1 ) {
    	
		if (fw_perform( (gchar*)"DenyCmd", conf, p,NULL) == 0) {
			
			peer_free(p);
			p->status = 1;
		} else {
			return -1;
		}
    }
    //g_message("peer status = %d",p->status);
    return 0;
}

//# ifdef HAVE_LIBCRYPT

gchar* get_peer_token ( peer *p ) {
    char *n;
    int carry = 1;

    g_assert( p != NULL );
    
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
