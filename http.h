# define MAX_REQUEST_SIZE 100000L
# define HEADER(x) (h->header == NULL ? NULL : \
	(gchar*)g_hash_table_lookup(h->header, (x)))
# define QUERY(x)  (h->query == NULL  ? NULL : \
	(gchar *)g_hash_table_lookup(h->query, (x)))

typedef struct {
    gchar* uri;
    gchar* method;
    GHashTable* header;				// Llenado en http_request_read()
    GHashTable* query;				// Llenado en http_request_ok()
    GHashTable* response;
    GString* buffer;				// Inicializado en http_request_new() a "", llenado en http_request_read
    gboolean complete;
    GIOChannel* sock;				// Inicializado en http_request_new()
    gchar peer_ip[16];				// Inicializado en http_request_new()
    unsigned short int remote_port;
    gchar sock_ip[16];				// Inicializado en http_request_new()
    gboolean is_used;
} http_request;

class h_requests {

	unsigned int cantidad;
	
	public:
	
	http_request** items;
	
	h_requests();
	~h_requests();
	
	http_request* add(GIOChannel* sock);
	void remove(http_request* h);
	http_request* get(unsigned int index);
	int get_index(http_request* h);
	void get_ride_of_sombies();
	
};

/*** Function prototypes start here ***/
GIOChannel* http_bind_socket( const char *ip, int port, int queue );
http_request* http_request_new ( GIOChannel *sock );
void http_request_free ( http_request *h );
GHashTable* parse_query_string( gchar *query );
GHashTable* http_parse_header (http_request *h, gchar *req);
GHashTable* http_parse_query (http_request *h, gchar *post);
guint http_request_read (http_request *h);
gboolean http_request_ok (http_request *h);
void http_add_header ( http_request *h, const gchar *key, gchar *val );
void http_printf_header ( http_request *h, gchar *key, gchar *fmt, ... );
GIOError http_send_header ( http_request *h, int status, const gchar *msg );
void http_send_redirect( http_request *h, gchar *dest );

gchar *http_fix_path (const gchar *uri, const gchar *docroot);
gchar *http_mime_type (const gchar *path);
int http_open_file (const gchar *path, int *status);
ssize_t http_sendfile ( http_request *h, int in_fd );
int http_serve_file ( http_request *h, const gchar *docroot );
int http_serve_template ( http_request *h, gchar *file, GHashTable *data );

gboolean handle_read( GIOChannel *sock, GIOCondition cond, http_request *h );
