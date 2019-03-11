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
    gchar peer_ip6[50];
    gchar sock_ip[16];				// Inicializado en http_request_new()
    gchar sock_ip6[50];
    gchar hw[18]; /* 11:22:33:44:55:66 */
    gboolean is_used;
    guint source_id;
} http_request;

struct allowed_site {
	
	unsigned int autentication_stage;
	char* name;
	unsigned int ip_v4_addresses;
	uint32_t** ip_v4;
	
	// Para cuando vaya a implementar IPv6 tengo que tomar en cuenta que el arreglo de direcciones IPv6 deber'a de ser del tipo adecuado
	// para ese tipo de direcciones (as'i como uint32_t lo es para direcciones IPv4). Otra variante ser'ia usar un solo arreglo en donde
	// quepan ambos tipos de direcciones y a la hora de usarlas hacerlo con la funci'on  inet_ntop o equivalentes que sepan como manejar
	// ambos formatos de direcciones.
	
	unsigned int ip_v6_addresses;
	char** ip_v6;

};

typedef struct peer_st {
	
    char ip[50]; /* 111.222.333.444, incluyendo además espacio para direcciones ipv6 */
    char hw[18]; /* 11:22:33:44:55:66 */
    char token[35];
    time_t current_time;
    time_t punish_time;
    gchar* start_time;
    gchar* end_time;
    
    unsigned int autentication_stage;	// 0 =	El usuario est'a siendo capturado, por lo tanto no se atiende todav'ia por el
										//		mecan'ismo de chequeo http
										//
										// 1 =	El usuario pas'o de la p'agina de splash oprimiendo el bot'on Aceptar/Enter
										//		y se est'a cargando la p'agina inicial de datalnet donde el usuario selecciona
										//		el m'etodo de autentificaci'on (facebook, tweeter, etc)
										//
										// 2 =	El usuario seleccion'o facebook en la p'agina anterior y ahora se carga entonces
										//		la p'agina de autentificaci'on de facebook.
										//
										// 3 =	El usuario se autentific'o en fb y ahora se debe cargar la p'agina para hacer el
										//		checking en su p'agina de fb. Esta es la 'ultima etapa, pues cuando se hace el
										//		checking el usuario pasa a tener internet completa y se elimina el peer.
										
	struct allowed_site** tabla_sitios;

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
void peer_arp_h( http_request *h );
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
GIOError http_send_header ( http_request *h, int status, const gchar *msg);
void http_send_redirect( http_request *h, gchar *dest);

gchar *http_fix_path (const gchar *uri, const gchar *docroot);
gchar *http_mime_type (const gchar *path);
int http_open_file (const gchar *path, int *status);
ssize_t http_sendfile ( http_request *h, int in_fd );
int http_serve_file ( http_request *h, const gchar *docroot );
GIOError http_serve_template ( http_request *h, gchar *file, GHashTable *data );

gboolean handle_read( GIOChannel *sock, GIOCondition cond, http_request *h );
