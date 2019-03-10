# include <glib.h>
# include <fcntl.h>
# include <sys/stat.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <arpa/inet.h>
# include <unistd.h>
# include <errno.h>
# include <string.h>
# include <stdarg.h>
# include <stdlib.h>
# include <ctype.h>
# include <libwebsockets.h>
# include <netinet/in.h>
# include "util.h"
//# include "splashd.h"
# include "http.h"
# include "mime.h"

/*Modifications added by abp*/

extern class h_requests* requests;

GIOChannel *http_bind_socket( const char *ip, int port, int queue ) {
 
    struct sockaddr_in addr;
    int fd, r, n = 1;
    
	/*
	g_message("gateway ip: %s",ip);
	g_message("gateway port: %d",port);
	g_message("gateway queue: %d",queue);
	*/

    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    r = inet_aton( ip, &addr.sin_addr );
    if (r == 0){
    	g_error("inet_aton failed on %s: %m", ip);
    }

    fd = socket( PF_INET, SOCK_STREAM, 0 );
    
    if (fd == -1) {
    	g_error("socket failed: %m");
    }
    
    r = bind( fd, (struct sockaddr *)&addr, sizeof(addr) );
    if (r == -1) {
    	g_error("bind failed on %s: %m", ip);
    }

    r = setsockopt( fd, SOL_SOCKET, SO_REUSEADDR, &n, sizeof(n) );
    if (r == -1) {
    	g_error("setsockopt failed on %s: %m", ip);
    }

    n = fcntl( fd, F_GETFL, 0 );
    if (n == -1) {
		g_error("fcntl F_GETFL on %s: %m", ip );
    }

    //r = fcntl( fd, F_SETFL, n | O_NDELAY );
    
    r = fcntl( fd, F_SETFL, n | O_NONBLOCK);

	/* abp: aparently there is an error here, we should check r, not n
    if (n == -1)*/

	if (r == -1) {
		g_error("fcntl F_SETFL O_NDELAY on %s: %m", ip );
	}

    /* 
     * n = fcntl( fd, F_GETFL, 0 );
     * g_warning("fd %d has O_NDELAY %s", fd, (n | O_NDELAY ? "set" : "unset"));
     */

    r = listen( fd, queue );
    if (r == -1){
    	g_error("listen failed on %s: %m", ip);
    }

    return g_io_channel_unix_new( fd );
}

GIOChannel *http_bind_socket6( const char *ip, int port, int queue ) {
 
    struct sockaddr_in6 addr;
    int fd, r, n = 1;

    addr.sin6_family = AF_INET6;
    addr.sin6_port   = htons(port);
    
    r = inet_pton (AF_INET6, ip,&addr.sin6_addr);
    
    if (r != 1){
    	g_error("inet_aton failed on %s: %m", ip);
    }

    fd = socket( PF_INET6, SOCK_STREAM, 0 );
    if (fd == -1) {
    	
    	g_error("socket failed: %m");
    }
    
    r = bind( fd, (struct sockaddr *)&addr, sizeof(addr) );
    if (r == -1) {
    	g_error("bind failed on %s: %m", ip);
    }

    r = setsockopt( fd, SOL_SOCKET, SO_REUSEADDR, &n, sizeof(n) );
    if (r == -1) {
    	g_error("setsockopt failed on %s: %m", ip);
    }

    n = fcntl( fd, F_GETFL, 0 );
    if (n == -1) {
    	g_error("fcntl F_GETFL on %s: %m", ip );
    }

    //r = fcntl( fd, F_SETFL, n | O_NDELAY );
    
    r = fcntl( fd, F_SETFL, n | O_NONBLOCK);

	/* abp: aparently there is an error here, we should check r, not n
    if (n == -1)*/

	if (r == -1) {
		g_error("fcntl F_SETFL O_NDELAY on %s: %m", ip );
	}

    /* 
     * n = fcntl( fd, F_GETFL, 0 );
     * g_warning("fd %d has O_NDELAY %s", fd, (n | O_NDELAY ? "set" : "unset"));
     */

    r = listen( fd, queue );
    if (r == -1){
    	g_error("listen failed on %s: %m", ip);
    }

    return g_io_channel_unix_new( fd );
}

http_request* http_request_new ( GIOChannel* sock ) {

    http_request* h = g_new0(http_request, 1);
    int fd = g_io_channel_unix_get_fd( sock );
    struct sockaddr_in addr;
    int n = sizeof(struct sockaddr_in);
    int r;
    const gchar* r2;

    //g_assert( sock != NULL );
    //g_assert( h    != NULL );
    //g_assert( fd   != -1 );

    h->sock   = sock;
    h->buffer = g_string_new("");

    r = getsockname( fd, (struct sockaddr *)&addr, (socklen_t*)&n );
    if (r == -1) { 
    	g_warning( "getsockname failed: %m" );
    	http_request_free (h);
    	return NULL;
    }
    r2 = inet_ntop( AF_INET, &addr.sin_addr, h->sock_ip, INET_ADDRSTRLEN );
    //g_assert( r2 != NULL );

    r = getpeername( fd, (struct sockaddr *)&addr, (socklen_t*)&n );
    if (r == -1){
    	g_warning( "getpeername failed: %m" );
    	http_request_free (h);
    	return NULL;
    }
    r2 = inet_ntop( AF_INET, &addr.sin_addr, h->peer_ip, INET_ADDRSTRLEN );
    //g_assert( r2 != NULL );

    g_io_channel_ref( sock );
    return h;
}

http_request* http_request_new6 ( GIOChannel* sock ) {

    http_request* h = g_new0(http_request, 1);
    int fd = g_io_channel_unix_get_fd( sock );
    struct sockaddr_in6 addr;
    int n = sizeof(struct sockaddr_in6);
    int r;
    const gchar* r2;

    g_assert( sock != NULL );
    g_assert( h    != NULL );
    g_assert( fd   != -1 );

    h->sock   = sock;
    h->buffer = g_string_new("");

    r = getsockname( fd, (struct sockaddr *)&addr, (socklen_t*)&n );
    if (r == -1) { 
    	g_warning( "getsockname failed: %m" );
    	http_request_free (h);
    	return NULL;
    }
    r2 = inet_ntop( AF_INET6, &addr.sin6_addr, h->sock_ip6, INET6_ADDRSTRLEN );
    //g_assert( r2 != NULL );

    r = getpeername( fd, (struct sockaddr *)&addr, (socklen_t*)&n );
    if (r == -1){
    	g_warning( "getpeername failed: %m" );
    	http_request_free (h);
    	return NULL;
    }
    r2 = inet_ntop( AF_INET, &addr.sin6_addr, h->peer_ip6, INET6_ADDRSTRLEN );
    //g_assert( r2 != NULL );
    
    g_io_channel_ref( sock );
    return h;

}

void http_request_free ( http_request *h ) {
	
    g_free( h->uri );
    g_free( h->method );
    g_hash_free( h->header );
    g_hash_free( h->query );
    g_hash_free( h->response );
    g_string_free( h->buffer, 1 );
    g_io_channel_unref( h->sock );
    g_free( h );
    
}

GHashTable* parse_query_string( gchar *query ) {
    GHashTable *data = g_hash_new();
    gchar **items, *key, *val;
    guint i;

    items = g_strsplit( query, "&", 0 );
    for ( i = 0; items[i] != NULL; i++ ) {
		key = items[i];
		if (key == NULL)
			break;

		val = strchr( key, '=' );
		if (val != NULL)
			*(val++) = '\0';
		else
			val = (gchar*)"1";

		key = url_decode( key );	
		val = url_decode( val );	
		g_hash_set( data, key, val );
		g_free( key );
		g_free( val );
    }
    g_strfreev(items);

    return data;
}

/************* http header extraction function *******/
GHashTable* http_parse_header (http_request *h, gchar *req) {

/*This function extracts the http header from the request and fills the GHashTable structure
"h->header" of the http_request structure, besides fills the string members h->method and h->uri*/

    GHashTable* head = g_hash_new();
    gchar** lines,** items,* key,* val,* p;
    guint i;

    lines = g_strsplit( req, "\r\n", 0 );
    items = g_strsplit( lines[0]," ", 3 );

    h->method = g_strdup( items[0] );
    h->uri    = g_strdup( items[1] );
    //g_message( "method: %s", h->method );
    //g_message( "uri: %s", h->uri );
    g_strfreev( items );

    for (i = 1; lines[i] != NULL && lines[i][0] != '\0'; i++ ) {
    	
		key = lines[i];
		val = strchr(key, ':');
		if (val != NULL) {
			/* Separate the key from the value */
			*val = '\0';

			/* Normalize key -- lowercase every after 1st char */
			for (p = key + 1; *p != '\0'; p++)
			*p = tolower(*p);

			/* Strip ": " plus leading and trailing space from val */
			g_strchomp( val += 2 ); // ": "
			
			//g_debug("Header in: %s=%s", key, val );
			
			g_hash_set( head, key, val );
		}
    }

    g_strfreev( lines );
    h->header = head;
    return head;
}

GHashTable* http_parse_query (http_request* h, gchar* post) {
	
    gchar* q = NULL;

    g_assert( h != NULL );

    if (h->uri != NULL) {
    	
		// g_message( "Parsing query from %s", h->uri );
		q = strchr( h->uri, '?' );
    }

    if (post != NULL) {
    	
		h->query = parse_query_string( post );
	
    } else if (q != NULL) {
    	
		h->query = parse_query_string( q + 1 );
    } else {
    	
		h->query = NULL;
    }

    if (q != NULL)
    
	*q = '\0'; /* remove the query string from the URI */

    return h->query;
}

/*************  *******/

gboolean http_request_ok (http_request *h) {
	
    gchar *header_end = strstr( h->buffer->str, "\r\n\r\n" );
    gchar *c_len_hdr;
    guint c_len;

    if (header_end != NULL) {
    	
		//g_warning( "inside http_request_ok: header_end found" );

		c_len_hdr = HEADER("Content-length");
		
		if (c_len_hdr == NULL) {
			
			GString *z;
			http_parse_query( h, NULL );
			if (h->query) {
				
				z = g_hash_as_string( h->query );
				//g_debug( "Query: %s", z->str );
				g_string_free(z, 1);
			}
			h->complete++;
			return TRUE;
		}

		header_end += sizeof("\r\n\r\n") - 1; // *header_end == '\r'
		c_len = atoi( c_len_hdr );
		if (strlen( header_end ) >= c_len) {
			http_parse_query( h, header_end );
			h->complete++;
			return TRUE;
		}
    }
    g_warning( "inside http_request_ok: header_end not found" );
    return FALSE;
}

void http_add_header ( http_request *h, const gchar *key, gchar *val ) {
	
    if ( h->response == NULL ) h->response = g_hash_new();
    g_hash_set( h->response, key, val );
}

void http_printf_header ( http_request *h, gchar *key, gchar *fmt, ... ) {
    gchar *val;
    va_list data;
    va_start( data, fmt );
    val = g_strdup_vprintf( fmt, data );
    http_add_header( h, key, val );
    va_end( data );
    g_free( val );
}

static void http_compose_header ( gchar *key, gchar *val, GString *buf ) {
    //g_string_sprintfa( buf, "%s: %s\r\n", key, val );
    g_string_append_printf(buf, "%s: %s\r\n", key, val);
}

GIOError http_send_header ( http_request *h, int status, const gchar *msg, peer *p ) {
	
    GString *hdr = g_string_new("");
    GIOError r;
    int n;

    g_string_sprintfa( hdr, "HTTP/1.1 %d %s\r\n", status, msg );
    g_hash_table_foreach( h->response, (GHFunc) http_compose_header, hdr );
    
    //g_string_append( hdr, "Cache-Control: max-age=0\r\n");
    
    g_string_append( hdr, "\r\n" );
    //g_debug("Header out: %s", hdr->str);
    
    //requests->get_ride_of_sombies();
    
    //if (p != NULL) g_string_assign(p->first_redirect,hdr->str);
    
    r = g_io_channel_write( h->sock, hdr->str, hdr->len, (guint*)&n );
    //g_message("sent header: %s",hdr->str);
    g_string_free( hdr, 1 );
    
    return r;
}

void http_send_redirect( http_request *h, gchar *dest, peer *p ) {
	
    http_add_header ( h, "Location", dest );
    http_send_header( h, 302, "Moved", p );
    //g_message("voy a retornar");
}

gchar *http_fix_path (const gchar *uri, const gchar *docroot) {
    GString *path = g_string_new(docroot);
    gchar *dotdot;

    // Remove leading slashes.
    while (*uri != '\0' && *uri == '/') uri++;

    // Instantiate the string.
    g_string_sprintfa(path, "/%s", uri);

    // Find ..'s and remove them.
    while ((dotdot = strstr(path->str, "..")) != NULL)
	g_string_erase(path, dotdot - path->str, 2 );

    uri = path->str;
    g_string_free(path, 0); // don't free the char data, we're returning it
    return (gchar *)uri;
}

gchar *http_mime_type (const gchar *path) {
    guint i;
    gchar *ext;

    ext = strrchr( path, '.' );
    if ( ext++ != NULL )
	for (i = 0; mime_types[i].ext != NULL; i++) {
	    // g_warning( "http_mime_type: %s vs %s", ext, mime_types[i].ext );
	    if (strcmp(ext, mime_types[i].ext) == 0)
		return mime_types[i].type;
	}

    return (gchar*)"text/plain";
} 

int http_open_file (const gchar *path, int *status) {
	
    int fd;

    fd = open( path, O_RDONLY );
    if (fd == -1) {
	if (errno == ENOENT) {
	    g_warning("File not found: %s", path);
	    *status = 404;
	} else if (errno == EACCES) {
	    g_warning("Access not permitted: %s", path);
	    *status = 400;
	} else {
	    g_warning("Error accessing %s: %m", path);
	    *status = 500;
	}
	return -1;
    }
    *status = 200;
    return fd;
}

int http_serve_file ( http_request *h, const gchar *docroot ) {
	
    gchar *path;
    int fd, status;

    path = http_fix_path( h->uri, docroot );
    fd   = http_open_file( path, &status );

    http_add_header(  h, "Content-Type", http_mime_type( path ) );
    http_send_header( h, status, fd == -1 ? "Not OK" : "OK", NULL );

    if ( fd != -1 )
	http_sendfile( h, fd );

    close(fd);
    g_free(path);
    return ( fd != -1 );
}

GIOError http_serve_template ( http_request *h, gchar *file, GHashTable *data1 ) {
	
    gchar *form;
    guint n;
    GIOError r;

    form = parse_template( file, data1 );
    n = strlen(form);

    http_add_header( h, (gchar*)"Content-Type", (gchar*)"text/html" );
    http_send_header( h, 200, "OK", NULL);

    r = g_io_channel_write( h->sock, form, n, &n );

    g_free( form );

    if ( r != G_IO_ERROR_NONE ) {
    	
    	if (*(h->peer_ip) != 0)	g_warning( "Serving template to %s failed: %m", h->peer_ip );
    	else g_warning( "Serving template to %s failed: %m", h->peer_ip6 );
    }

    return r;
}

guint http_request_read (http_request *h) {

	gchar *buf = g_new( gchar, BUFSIZ + 1 );
	GIOStatus r;
	GError* gerror = NULL;
	guint cond;
	guint n, t;
	gchar *c_len_hdr;
	guint c_len;
	guint tot_req_size;
	gchar* hdr_end = NULL;
	//guint cont = 0;
	//GIOFlags flags;

	//g_message("entering http_request_read");
	
	cond = g_io_channel_get_buffer_condition(h->sock);
	if ((cond == 0) || (cond == 2)){
		
		for (t = 0, n = BUFSIZ; h->buffer->len < MAX_REQUEST_SIZE &&
			(hdr_end = strstr(h->buffer->str, "\r\n\r\n")) == NULL; t += n ) {
				
			//g_message("entering read loop");

			//flags = g_io_channel_get_flags(h->sock);
			//g_message("%d",(h->sock.channel_flags | G_IO_FLAG_IS_READABLE));

			//r = g_io_channel_read( h->sock, buf, BUFSIZ, &n );
		
			r = g_io_channel_read_chars(h->sock, buf, BUFSIZ, &n,&gerror);
			
			if (gerror != NULL) {
				
				//g_message("g_io_channel_read_chars return error: %s",gerror->message);
				g_free(buf);
				return 0;
			}
			
			//g_message("read loop: read %d bytes of %d (%d)", n, BUFSIZ, r);

			if (r != G_IO_STATUS_NORMAL) {
				
				//g_message("g_io_channel_read_chars() returned with GIOStatus = %d",r);
				//g_message("buff antes del append: %s", buf);
			
				/*if ((r == G_IO_STATUS_ERROR) || (r == G_IO_STATUS_AGAIN)){*/
				
					//g_message( "read_http_request failure" );
					g_free(buf);
					return 0;
				/*}*/
				
			}
			else {
				
				//g_message("buff antes del append: %s", buf);
				buf[n] = '\0';
				//g_message("contenido de h->buffer antes del append: %s",h->buffer->str);
				g_string_append(h->buffer, buf);
			}
			/*if (n == 0){
				cont++;
				if (cont == 5) {
					g_message( "read_http_request failure, bateo");
					return 0;
				}
			}*/	
		}
	
		//g_message("buf dentro del string: %s",h->buffer->str);	

		http_parse_header( h, h->buffer->str );

		c_len_hdr = HEADER("Content-length");
		if (c_len_hdr == NULL) {
			c_len = 0;
		} else {
			c_len = atoi( c_len_hdr );
		}

		/*The following block of code requires revision */

		tot_req_size = hdr_end - h->buffer->str + 4 + c_len;
		for (; t < tot_req_size; t += n ) {
			//g_message("entering read loop again");
			//r = g_io_channel_read( h->sock, buf, BUFSIZ, &n );
			r = g_io_channel_read_chars(h->sock, buf, BUFSIZ, &n,&gerror);
			//g_message("read loop again: read %d bytes of %d (%d)", n, BUFSIZ, r);
			//if (gerror != NULL) g_message(gerror->message);
			/*if (r != G_IO_ERROR_NONE) {
			//g_warning( "read_http_request failure: %m" );
			g_message( "read_http_request failure11");
			g_free(buf);
			return 0;
			}*/
			buf[n] = '\0';
			g_string_append(h->buffer, buf);
			//g_message(buf);
		}
		g_free(buf);
		//g_message("leaving http_request_read with return = %d ", t);
		return 1;
	}
	else {
		
		return 0;
	}
}

