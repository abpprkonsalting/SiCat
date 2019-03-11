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

extern struct hs_array_t* hs_array;

GIOChannel *http_bind_socket( const char *ip, int port, int queue ) {
 
    struct sockaddr_in addr;
    int fd, r, n = 1;
    
	g_debug("http_bind_socket: gateway ip: %s",ip);
	g_debug("http_bind_socket: gateway port: %d",port);
	g_debug("http_bind_socket: gateway queue: %d",queue);

    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    r = inet_aton( ip, &addr.sin_addr );
    if (r == 0){
    	//g_error("http_bind_socket: inet_aton failed on %s: %m", ip);
    	g_message("http_bind_socket: inet_aton failed on %s: %m", ip);
    	g_assert(0);
    }

    fd = socket( PF_INET, SOCK_STREAM, 0 );
    
    if (fd == -1) {
    	//g_error("http_bind_socket: socket failed: %m");
    	g_message("http_bind_socket: socket failed: %m");
    	g_assert(0);
    }
    
    r = bind( fd, (struct sockaddr *)&addr, sizeof(addr) );
    if (r == -1) {
    	//g_error("http_bind_socket: bind failed on %s: %m", ip);
    	g_message("http_bind_socket: bind failed on %s: %m", ip);
    	g_assert(0);
    }

    r = setsockopt( fd, SOL_SOCKET, SO_REUSEADDR, &n, sizeof(n) );
    if (r == -1) {
    	//g_error("http_bind_socket: setsockopt failed on %s: %m", ip);
    	g_message("http_bind_socket: setsockopt failed on %s: %m", ip);
    	g_assert(0);
    }

    n = fcntl( fd, F_GETFL, 0 );
    if (n == -1) {
		//g_error("http_bind_socket: fcntl F_GETFL on %s: %m", ip );
		g_message("http_bind_socket: fcntl F_GETFL on %s: %m", ip);
    	g_assert(0);
    }
    
    r = fcntl( fd, F_SETFL, n | O_NONBLOCK);

	/* abp: aparently there is an error here, we should check r, not n
    if (n == -1)*/

	if (r == -1) {
		//g_error("http_bind_socket: fcntl F_SETFL O_NONBLOCK on %s: %m", ip );
		g_message("http_bind_socket: fcntl F_SETFL O_NONBLOCK on %s: %m", ip );
    	g_assert(0);
	}

    r = listen( fd, queue );
    if (r == -1){
    	//g_error("http_bind_socket: listen failed on %s: %m", ip);
    	g_message("http_bind_socket: listen failed on %s: %m", ip);
    	g_assert(0);
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
    	g_error("http_bind_socket6: inet_aton failed on %s: %m", ip);
    }

    fd = socket( PF_INET6, SOCK_STREAM, 0 );
    if (fd == -1) {
    	
    	g_error("http_bind_socket6: socket failed: %m");
    }
    
    r = bind( fd, (struct sockaddr *)&addr, sizeof(addr) );
    if (r == -1) {
    	g_error("http_bind_socket6: bind failed on %s: %m", ip);
    }

    r = setsockopt( fd, SOL_SOCKET, SO_REUSEADDR, &n, sizeof(n) );
    if (r == -1) {
    	g_error("http_bind_socket6: setsockopt failed on %s: %m", ip);
    }

    n = fcntl( fd, F_GETFL, 0 );
    if (n == -1) {
    	g_error("http_bind_socket6: fcntl F_GETFL on %s: %m", ip );
    }
    
    r = fcntl( fd, F_SETFL, n | O_NONBLOCK);

	/* abp: aparently there is an error here, we should check r, not n
    if (n == -1)*/

	if (r == -1) {
		g_error("http_bind_socket6: fcntl F_SETFL O_NDELAY on %s: %m", ip );
	}

    r = listen( fd, queue );
    if (r == -1){
    	g_error("http_bind_socket6: listen failed on %s: %m", ip);
    }

    return g_io_channel_unix_new( fd );
}

void peer_arp_h( http_request *h ) {
    gchar ip[50], hw[18];
    FILE *arp;

    arp = fopen( "/proc/net/arp", "r" );
    if ( arp == NULL ){
    	g_warning( "Can't open /proc/net/arp: %m" );
    	return;
    }
   
    fscanf(arp, "%*s %*s %*s %*s %*s %*s %*s %*s %*s"); // Skip first line 
    while (fscanf( arp, "%15s %*s %*s %17s %*s %*s\n", ip, hw ) != EOF)
    {
		if ( strncmp( h->peer_ip, ip, sizeof(h->peer_ip) ) == 0 ) 
			{
				g_strncpy( h->hw, hw, sizeof(h->hw) );
				break;
			}
    }

    fclose( arp );
}

http_request* http_request_new ( GIOChannel* sock,int fd ) {

    http_request* h = g_new0(http_request, 1);
    struct sockaddr_in addr;
    int n = sizeof(struct sockaddr_in);
    int r;
    const gchar* r2;

    h->sock   = sock;
    h->buffer = g_string_new("");
    h->is_used = FALSE;
	h->source_id = 0;
    r = getsockname( fd, (struct sockaddr *)&addr, (socklen_t*)&n );
    if (r == -1) { 
    	g_warning( "http_request_new: getsockname failed: %m" );
    	http_request_free (h);
    	return NULL;
    }
    r2 = inet_ntop( AF_INET, &addr.sin_addr, h->sock_ip, INET_ADDRSTRLEN );

    r = getpeername( fd, (struct sockaddr *)&addr, (socklen_t*)&n );
    if (r == -1){
    	g_warning( "http_request_new: getpeername failed: %m" );
    	http_request_free (h);
    	return NULL;
    }
    r2 = inet_ntop( AF_INET, &addr.sin_addr, h->peer_ip, INET_ADDRSTRLEN );
    
	peer_arp_h(h);
	
    return h;
}

http_request* http_request_new6 ( GIOChannel* sock,int fd ) {

    http_request* h = g_new0(http_request, 1);
    //int fd = g_io_channel_unix_get_fd( sock );
    struct sockaddr_in6 addr;
    int n = sizeof(struct sockaddr_in6);
    int r;
    const gchar* r2;

    h->sock   = sock;
    h->buffer = g_string_new("");
    h->is_used = FALSE;

    r = getsockname( fd, (struct sockaddr *)&addr, (socklen_t*)&n );
    if (r == -1) { 
    	g_warning( "http_request_new6: getsockname failed: %m" );
    	http_request_free (h);
    	return NULL;
    }
    r2 = inet_ntop( AF_INET6, &addr.sin6_addr, h->sock_ip6, INET6_ADDRSTRLEN );

    r = getpeername( fd, (struct sockaddr *)&addr, (socklen_t*)&n );
    if (r == -1){
    	g_warning( "http_request_new6: getpeername failed: %m" );
    	http_request_free (h);
    	return NULL;
    }
    r2 = inet_ntop( AF_INET, &addr.sin6_addr, h->peer_ip6, INET6_ADDRSTRLEN );
    
    return h;

}

void http_request_free ( http_request *h ) {
	
    g_free( h->uri );
    g_free(h->uri_orig);
    g_free( h->method );
    g_hash_free( h->header );
    g_hash_free( h->query );
    g_hash_free( h->response );
    g_string_free( h->buffer, TRUE );
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
		//g_debug("parse_query_string: key/value: %s = %s",key,val);
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
    h->uri_orig = g_strdup( items[1] );
    
    //g_debug( "http_parse_header: method= %s", h->method );
    //g_debug( "http_parse_header: uri= %s", h->uri );
    
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
			
			//g_debug("http_parse_header: Header in: %s=%s", key, val );
			
			g_hash_set( head, key, val );
		}
    }

    g_strfreev( lines );
    
    if (h->header != NULL) g_hash_free(h->header);
    h->header = head;
    return head;
}

GHashTable* http_parse_query (http_request* h, gchar* post) {
	
    gchar* q = NULL;

    //g_assert( h != NULL );

    if (h->uri != NULL) {
    	
		// g_message( "Parsing query from %s", h->uri );
		q = strchr( h->uri, '?' );
    }

    if (post != NULL) {
    	
		h->query = parse_query_string( post );
	
    }
    else if (q != NULL) {
    	
		h->query = parse_query_string( q + 1 );
    } else {
    	
		h->query = NULL;
    }

    if (q != NULL) *q = '\0'; /* remove the query string from the URI */

    return h->query;
}

/*************  *******/

gboolean http_request_ok (http_request *h) {
	
    gchar *header_end = strstr( h->buffer->str, "\r\n\r\n" );
    gchar *c_len_hdr;
    long int c_len;

	//g_debug( "http_request_ok, entering..");
    if (header_end != NULL) {

		c_len_hdr = HEADER("Content-length");
		
		if (c_len_hdr == NULL) {
			
			GString *z;
			http_parse_query( h, NULL );
			if (h->query) {
				
				z = g_hash_as_string( h->query );
				//g_debug( "http_request_ok: Query: %s", z->str );
				g_string_free(z, 1);
			}
			h->complete++;
			//g_debug( "http_request_ok, leaving..");
			return TRUE;
		}

		header_end += sizeof("\r\n\r\n") - 1; // *header_end == '\r'
		
		c_len = strtol (c_len_hdr, NULL, 10);
		//c_len = atoi( c_len_hdr );
		
		if (c_len > 0) {
			
			if (strlen(header_end) >= c_len) {
				http_parse_query(h, header_end);
				h->complete++;
				//g_debug( "http_request_ok, leaving..");
				return TRUE;
			}
		}
    }
    //g_debug( "http_request_ok, leaving..");
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
	
	//g_debug("http_compose_header: entering..");
    //g_string_sprintfa( buf, "%s: %s\r\n", key, val );
    g_string_append_printf(buf, "%s: %s\r\n", key, val);
    //g_debug("http_compose_header: leaving..");
}

/*GIOStatus http_send_header ( http_request *h, int status, const gchar *msg, peer *p ) {
	
    GString *hdr = g_string_new("");
    GIOStatus r;
    guint n;
    GError* gerror = NULL;

    g_string_sprintfa( hdr, "HTTP/1.1 %d %s\r\n", status, msg );
    g_hash_table_foreach( h->response, (GHFunc) http_compose_header, hdr );
    
    g_string_append( hdr, "\r\n" );
    
    //r = g_io_channel_write_chars(h->sock, hdr->str, hdr->len,&n,&gerror);
    r = g_io_channel_write_chars(h->sock, hdr->str,strlen(hdr->str),&n,&gerror);
    
    if (gerror != NULL) {
				
		g_warning("http_send_header: g_io_channel_write_chars error: %s",gerror->message);
		g_warning("http_send_header: could't sent header= %s to peer %s",hdr->str, h->peer_ip);
	}
	else {
    
		if (*(h->sock_ip) != 0) g_debug ("http_send_header: sent header= %s to peer %s",hdr->str, h->peer_ip);
		else g_debug ("http_send_header: sent header= %s to peer %s",hdr->str, h->peer_ip6);
	}
    g_string_free( hdr, 1 );
    
    return r;
}*/

GIOError http_send_header (http_request *h, int status, const gchar *msg, peer *p ) {
	
    GString *hdr = g_string_new("");
    GIOError r;
    int n;

    g_string_sprintfa( hdr, "HTTP/1.1 %d %s\r\n", status, msg );
    g_hash_table_foreach( h->response, (GHFunc) http_compose_header, hdr );
    
    g_string_append( hdr, "\r\n" );
    
    //r = g_io_channel_write( h->sock, hdr->str, hdr->len, (guint*)&n );
    
    g_io_channel_write_chars(h->sock, hdr->str,hdr->len,(guint*)&n,NULL);
    g_io_channel_flush(h->sock,NULL);
    
    g_debug ("http_send_header: sent header= %s to peer %s",hdr->str, h->peer_ip);
    
    g_string_free( hdr, 1 );
    
    return r;
}

void http_send_redirect( http_request *h, gchar *dest, peer *p ) {
	
    http_add_header ( h, "Location", dest );
    http_add_header ( h, "Connection", "close");
    http_send_header( h, 307, "Temporary Redirect", p );    
}

void http_send_redirect1( http_request *h, gchar *dest, peer *p ) {
	
    http_add_header ( h, "Location", dest );
    http_add_header ( h, "Connection", "close");
    http_send_header( h, 303, "See Other", p );    
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

    ext =  (gchar*)strrchr( path,'.' );
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
	    g_warning("http_open_file: File not found: %s", path);
	    *status = 404;
	} else if (errno == EACCES) {
	    g_warning("http_open_file: Access not permitted: %s", path);
	    *status = 400;
	} else {
	    g_warning("http_open_file: Error accessing %s: %m", path);
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
    http_add_header ( h, "Connection", "close");
    http_send_header( h, status, fd == -1 ? "Not OK" : "OK", NULL );

    if ( fd != -1 )
	http_sendfile( h, fd );

    close(fd);
    g_free(path);
    return ( fd != -1 );
}

/*GIOStatus http_serve_template ( http_request *h, gchar *file, GHashTable *data1 ) {
	
    gchar *form;
    guint n;
    GIOStatus r;
    GError* gerror = NULL;

    form = parse_template( file, data1 );
    n = strlen(form);

    http_add_header( h, (gchar*)"Content-Type", (gchar*)"text/html" );
    http_send_header( h, 200, "OK", NULL);

    //r = g_io_channel_write( h->sock, form, n, &n );
    r = g_io_channel_write_chars(h->sock, form, n,&n,&gerror);
    
    if (gerror != NULL) {
				
		g_warning("http_serve_template: g_io_channel_write_chars error: %s",gerror->message);
		g_warning("http_serve_template: could't sent template to peer %s", h->peer_ip);
	}

    if (r != G_IO_STATUS_NORMAL) {
    	
    	if (*(h->peer_ip) != 0)	g_warning( "http_serve_template: Serving template to %s failed: %m", h->peer_ip );
    	else g_warning( "http_serve_template: Serving template to %s failed: %m", h->peer_ip6 );
    }
	g_free(form);

    return r;
}*/

GIOError http_serve_template ( http_request *h, gchar *file, GHashTable *data1 ) {
	
    gchar *form;
    guint n;
    GIOError r;

    form = parse_template( file, data1 );
    n = strlen(form);

    http_add_header( h, (gchar*)"Content-Type", (gchar*)"text/html" );
    http_add_header ( h, "Connection", "close");
    http_send_header( h, 200, "OK", NULL);

    //r = g_io_channel_write( h->sock, form, n, &n );
    g_io_channel_write_chars( h->sock, form, n, &n ,NULL);
    g_io_channel_flush(h->sock,NULL);

    g_free( form );

    if ( r != G_IO_ERROR_NONE ) {
    	
    	if (*(h->peer_ip) != 0)	g_warning( "http_serve_template: Serving template to %s failed: %m", h->peer_ip );
    	else g_warning( "http_serve_template: Serving template to %s failed: %m", h->peer_ip6 );
    }

    return r;
}

guint http_request_read (http_request *h) {

	gchar *buf, *buf1;
	gsize channel_size;
	GIOStatus r;
	GError* gerror = NULL;
	guint cond;
	guint n;
	gchar *c_len_hdr;
	long int c_len;
	
	//g_debug("http_request_read: entering..");

	cond = g_io_channel_get_buffer_condition(h->sock);
	
	if ((cond == 0) || (cond == 2)){
		
		channel_size = g_io_channel_get_buffer_size(h->sock);
		
		//g_debug("http_request_read: channel_size = %d",channel_size);
		
		buf = g_new0( gchar, channel_size + 2 );
		
		r = g_io_channel_read_chars(h->sock, buf, channel_size, &n,&gerror);
		
		if (gerror != NULL) {
				
			g_warning("http_request_read: g_io_channel_read_chars return error: %s",gerror->message);
			g_free(buf);
			return 2;
		}
		
		/*if ((r != G_IO_STATUS_NORMAL) || (r != G_IO_STATUS_EOF))  {
			
			g_warning("g_io_channel_read_chars() returned with GIOStatus = %d",r);
			g_free(buf);
			return 2;

		}*/
		
		//g_debug("http_request_read: caracteres leidos: %d", n);
		
		if (n == 0){

			g_free(buf);
			g_debug("http_request_read: leaving with error..");
			return 2;
		}
		
		buf1 = g_new0( gchar, n + 2);
		
		memcpy(buf1,buf,n);
		
		g_free(buf);
		buf = NULL;
		
		g_string_append(h->buffer, buf1);
		
		g_free(buf1);
		buf1 = NULL;
		
		h->is_used = TRUE;
		
		//g_debug("http_request_read: request= %s",h->buffer->str);
		
		gchar *header_end = strstr( h->buffer->str,"\r\n\r\n" );
		
		if (header_end != NULL){
					
			http_parse_header(h, h->buffer->str);
			
			c_len_hdr = HEADER("Content-length");
			
			if (c_len_hdr != NULL) {
				
				//c_len = atoi(c_len_hdr);
				c_len = strtol (c_len_hdr, NULL, 10);
				
				if (c_len > 0) {
					
					if ((long int)((strlen(h->buffer->str) - ((header_end + 4) - h->buffer->str))) < c_len){
						
						// Aún no ha llegado todo el mensaje
						g_debug("http_request_read: incomplete message, channel get open waiting for remaining data");
						return 0;
					}
					else if ((long int)((strlen(h->buffer->str) - ((header_end + 4) - h->buffer->str))) > c_len){
						
						g_warning("http_request_read: Data arrived mitmatch Header Content-length, discarting http request");
						return 2;
											
					}
				}
				else if (c_len < 0) {
					
					g_warning("http_request_read: Header Content-length negative or corrupt, discarting http request");
					return 2;
				}
			}
			//g_debug("http_request_read: leaving..");
			return 1;
			
		}
		else {
			
			// No se encontró el header end, por lo tanto retornamos 0 para que el channel siga abierto
			// retornando TRUE desde handle_read.
			
			g_debug("http_request_read: header end not found, channel get open waiting for remaining data");
			return 0;
		}
	}
	else {
		
		g_debug("http_request_read: g_io_channel_get_buffer_condition on request from %s return with buffer condition = %d", h->peer_ip, cond);
		return 2;
	}
}
