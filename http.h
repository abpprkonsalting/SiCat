# include <glib.h>

# include <sys/socket.h>
# include <netinet/in.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <signal.h>
# include <fcntl.h>
# include <unistd.h>
# include <syslog.h>
# include <stdlib.h>
# include <getopt.h>
# include <stdarg.h>
# include <stdio.h>
# include <string.h>
# include <arpa/inet.h>

# define MAX_REQUEST_SIZE 100000L
# define HEADER(x) (h->header == NULL ? NULL : \
	(gchar*)g_hash_table_lookup(h->header, (x)))
# define QUERY(x)  (h->query == NULL  ? NULL : \
	(gchar *)g_hash_table_lookup(h->query, (x)))

typedef struct {
    gchar* uri;
    gchar* uri_orig;
    gchar* method;
    GHashTable* header;				// Llenado en http_request_read()
    GHashTable* query;				// Llenado en http_request_ok()
    GHashTable* response;
    GString* buffer;				// Inicializado en http_request_new() a "", llenado en http_request_read
    gboolean complete;
    GIOChannel* channel;				// Inicializado en http_request_new()
    gchar peer_ip[16];				// Inicializado en http_request_new()
    unsigned short int peer_port;
    gchar peer_ip6[50];
    gchar sock_ip[16];				// Inicializado en http_request_new()
    gchar sock_ip6[50];
    gchar hw[18]; /* 11:22:33:44:55:66 */
    gboolean is_used;
    guint source_id;
	
} http_request;

struct otro_t {
	
	http_request* h;
	struct peer_st* p;
};

typedef struct peer_st {
	
    char ip[50]; /* 111.222.333.444, incluyendo además espacio para direcciones ipv6 */
    char hw[18]; /* 11:22:33:44:55:66 */
    char token[35];
    time_t current_time;
    time_t punish_time;
    time_t s_time;
    time_t e_time;
    gchar* start_time;
    gchar* end_time;
    
    unsigned char status;	// 0 = En proceso de autentificaci'on
							// 1 = Castigado.
							// 2 = Navegando por el grace period.
							// 3 = Navegando autorizado.
							
	unsigned int contador_b;
	unsigned int contador_m;
    gchar* p_uri_orig;
    
} peer;


/*** Function prototypes start here ***/
GIOChannel* http_bind_socket( const char *ip, int port, int queue );
GIOChannel *http_bind_socket6( const char *ip, int port, int queue );
void peer_arp_h( http_request *h );
http_request* http_request_new ( GIOChannel *channel,int fd );
http_request* http_request_new6 ( GIOChannel* channel,int fd  );
void http_request_free ( http_request *h );
GHashTable* parse_query_string( gchar *query );
GHashTable* http_parse_header (http_request *h, gchar *req);
GHashTable* http_parse_query (http_request *h, gchar *post);
guint http_request_read (http_request *h);
gboolean http_request_ok (http_request *h);
void http_add_header ( http_request *h, const gchar *key, gchar *val );
void http_printf_header ( http_request *h, gchar *key, gchar *fmt, ... );
void http_send_header ( http_request *h, int status, const gchar *msg, peer *p );
void http_send_redirect( http_request *h, gchar *dest, peer *p );
void http_send_redirect1( http_request *h, gchar *dest, peer *p );

gchar *http_fix_path (const gchar *uri, const gchar *docroot);
gchar *http_mime_type (const gchar *path);
int http_open_file (const gchar *path, int *status);
ssize_t http_sendfile ( http_request *h, int in_fd );
int http_serve_file ( http_request *h, const gchar *docroot );
void http_serve_template ( http_request *h, gchar *file, GHashTable *data );

gboolean handle_read( GIOChannel *channel, GIOCondition cond, http_request *h );
