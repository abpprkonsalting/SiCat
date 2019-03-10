# include <glib.h>
# include <stdio.h>
# include <unistd.h>
# include <string.h>
# include <sys/types.h>
# include <sys/wait.h>
# include <string.h>
# include <errno.h>
# include <time.h>
# include "firewall.h"

extern class h_requests* requests;
extern char **environ;

typedef struct {
    pid_t pid;
    gchar *cmd;
    peer *p;
} fw_action;

typedef struct {
	
	http_request* h;
	GString* dest;
} redire;

static void fw_exec_add_env ( gchar *key, gchar *val, GPtrArray *env ) {
    gchar *p;
    
    g_assert( key != NULL );
    g_assert( val != NULL );
    p = g_strdup_printf( "%s=%s", key, val );
    g_ptr_array_add( env, p );
}

static int fw_exec( fw_action *act, GHashTable *conf ) {
	
    GHashTable *data;
    GPtrArray *env;
    gchar *cmd, **arg, **n;

    data = g_hash_dup( conf );
    //
    // Than add specifics about this particular client, if any
    if (act->p != NULL) {
	g_hash_set( data, "IP",    act->p->ip );
	g_hash_set( data, "MAC",   act->p->hw );
	g_hash_set( data, (gchar*)"Class", (gchar*)"Public" );
    }

    cmd = conf_string( conf, act->cmd );
    cmd = parse_template( cmd, data );
    // g_message("Got command %s from action %s", cmd, act->cmd );
    arg = g_strsplit( cmd, " ", 0 );

    // prime the environment with our existing environment
    env = g_ptr_array_new();
    for ( n = environ; *n != NULL; n++ )
	g_ptr_array_add( env, *n );

    // Then add everything from the conf file
    g_hash_table_foreach( data, (GHFunc) fw_exec_add_env, env );

    // Add a closing NULL so execve knows where to lay off.
    g_ptr_array_add( env, NULL );

    /* We're not cleaning up memory references because 
     * hopefully the exec won't fail... */
    execve( *arg, arg, (char **)env->pdata );
    g_error( "execve %s failed: %m", cmd ); // Shouldn't happen.
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

static void http_compose_header ( gchar *key, gchar *val, GString *buf ) {
    g_string_sprintfa( buf, "%s: %s\r\n", key, val );
}

gboolean redirecciona_delayed ( redire* red ){
	
	http_send_redirect(red->h, red->dest->str);
	//g_message("regresé");
	g_string_free( red->dest, 1 );
	return FALSE;
}

void redirecciona(GPid pid,gint status,redire* red){
	
	requests->get_ride_of_sombies();
	g_timeout_add( 2000, (GSourceFunc)redirecciona_delayed, red );
	

	/*if ( red->h->response == NULL ) red->h->response = g_hash_new();
    g_hash_set( red->h->response, "Location", red->dest->str );
    
    GString *hdr = g_string_new("");
    GIOError r;
    int n;

    g_string_sprintfa( hdr, "HTTP/1.1 %d %s\r\n", 302, "Moved" );
    g_hash_table_foreach( red->h->response, (GHFunc) http_compose_header, hdr );
    g_string_append( hdr, "\r\n" );
    g_debug("Header out: %s", hdr->str);
    r = g_io_channel_write( red->h->sock, hdr->str, hdr->len, (guint*)&n );
    g_io_channel_flush(red->h->sock,NULL);
    g_message("sent header: %s",hdr->str);
    g_string_free( hdr, 1 );*/

	//return TRUE;
}

int fw_perform(gchar* action,GHashTable* conf,peer* p, http_request* h,	GString* dest) {
	
    fw_action* act = g_new( fw_action, 1 );
    pid_t pid;
    redire* red = g_new(redire,1);

    act->cmd = action;
    act->p   = p;
    
    if (h != NULL) red->h = h;
    if (dest != NULL) red->dest = dest;
	//g_message("antes del fork..");
    pid = fork();
    if (pid == -1){	g_error( "Can't fork: %m" );}
    
    if (h != NULL) {
    	 if (pid > 0) {
    	 	//g_message("añadiendo el watch");
    	 	g_child_watch_add (pid, (GChildWatchFunc)redirecciona,red);
    	 	//g_message("añadido el watch");
		}
	}
    
    if (! pid) {
    	sleep(1);
    	//g_message("ejecutando el fw_exec");
    	fw_exec( act, conf );
	}

    act->pid  = pid;
    //g_idle_add( (GSourceFunc) fw_cleanup, act );
    return 0;
}

int fw_init ( GHashTable *conf ) {
    return fw_perform( (gchar*)"ResetCmd", conf, NULL,NULL,NULL );
}

/******* peer.c routines **********/
void peer_extend_timeout( GHashTable* conf, peer* p, time_t ext ) {
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
    peer_extend_timeout(conf, p,conf_int( conf, "LoginTimeout" ));
    return p;
}

void peer_free ( peer *p ) {
    g_assert( p != NULL );
    if (p->request != NULL)
	g_free( p->request );
    g_free(p);
}

int peer_permit ( GHashTable* conf, peer* p, http_request* h,	GString* dest ) {
	
    /*g_assert( p != NULL );
    if (p->status != 0) {
		if (fw_perform( (gchar*)"PermitCmd", conf, p ) == 0) {
			p->status = 0;
		} else {
			return -1;
		}
    }
    peer_extend_timeout(conf, p);
    return 0;*/
    
    time_t extension = 0;
    //g_message("peer status = %d",p->status);
    if ((p->status == 0) || (p->status == 2)) {
    	
    	if (!(fw_perform( (gchar*)"PermitCmd", conf, p,h,dest ) == 0)) return -1;
    	
    	if (p->status == 0) 
    	{
    		extension = conf_int( conf, "LoginTimeout" );
		}
    	else 
    	{
    		extension = 180;
		}
	}
	peer_extend_timeout(conf, p, extension);
    return 0;
}

int peer_deny ( GHashTable *conf, peer *p ) {
	
    g_assert( p != NULL );
    //g_message("peer status = %d",p->status);
    if (p->status != 1 ) {
    	
		if (fw_perform( (gchar*)"DenyCmd", conf, p,NULL,NULL) == 0) {
			p->status = 1;
		} else {
			return -1;
		}
    }
    g_message("peer status = %d",p->status);
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
