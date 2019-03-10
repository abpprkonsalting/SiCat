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
    GIOChannel* sock;				// Inicializado en http_request_new()
    gchar peer_ip[16];				// Inicializado en http_request_new()
    gchar peer_ip6[50];
    gchar sock_ip[16];				// Inicializado en http_request_new()
    gchar sock_ip6[50];
    gboolean is_used;
} http_request;

typedef struct peer_st {
	
    char ip[50]; /* 111.222.333.444, incluyendo además espacio para direcciones ipv6 */
    char hw[18]; /* 11:22:33:44:55:66 */
    char token[35];
    time_t connected;
    time_t expire;
    
    //enum { PEER_ACCEPT, PEER_DENY } status;	//Esto tuve que cambiarlo para la linea 
    											//de abajo pues no me compilaba bien firewall.cc
    											//PEER_ACCEPT = 0
    											//PEER_DENY = 1
    											//PEER_ACEPT_TEMP = 2
    unsigned char status;
    
    
} peer;

class h_requests {

	unsigned int cantidad;
	
	public:
	
	http_request** items;
	
	h_requests();
	~h_requests();
	
	http_request* add(GIOChannel* sock);
	http_request* add6(GIOChannel* sock);
	void remove(http_request* h);
	http_request* get(unsigned int index);
	int get_index(http_request* h);
	void get_ride_of_sombies();
	
};

/*** Function prototypes start here ***/
GIOChannel* http_bind_socket( const char *ip, int port, int queue );
GIOChannel *http_bind_socket6( const char *ip, int port, int queue );
http_request* http_request_new ( GIOChannel *sock,int fd );
http_request* http_request_new6 ( GIOChannel* sock,int fd  );
void http_request_free ( http_request *h );
GHashTable* parse_query_string( gchar *query );
GHashTable* http_parse_header (http_request *h, gchar *req);
GHashTable* http_parse_query (http_request *h, gchar *post);
guint http_request_read (http_request *h);
gboolean http_request_ok (http_request *h);
void http_add_header ( http_request *h, const gchar *key, gchar *val );
void http_printf_header ( http_request *h, gchar *key, gchar *fmt, ... );
GIOError http_send_header ( http_request *h, int status, const gchar *msg, peer *p );
void http_send_redirect( http_request *h, gchar *dest, peer *p );

gchar *http_fix_path (const gchar *uri, const gchar *docroot);
gchar *http_mime_type (const gchar *path);
int http_open_file (const gchar *path, int *status);
ssize_t http_sendfile ( http_request *h, int in_fd );
int http_serve_file ( http_request *h, const gchar *docroot );
GIOError http_serve_template ( http_request *h, gchar *file, GHashTable *data );

gboolean handle_read( GIOChannel *sock, GIOCondition cond, http_request *h );
