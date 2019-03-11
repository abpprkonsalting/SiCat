
# include <glib.h>
# include <sys/types.h>
# include <openssl/ssl.h>
# include <openssl/err.h>
# include <openssl/evp.h>

# include <glib/gstdio.h>
# include <stdio.h>
# include <string.h>
# include <time.h>
# include <netinet/in.h>
# include <sys/socket.h>
# include <sys/stat.h>
# include <signal.h>
# include <fcntl.h>
# include <unistd.h>
# include <syslog.h>
# include <stdlib.h>
# include <getopt.h>
# include <stdarg.h>
# include <arpa/inet.h>
# include <errno.h>
# include <ctype.h>
# include <setjmp.h>

//#include "splashd.h"

#ifndef TLS_H
#define TLS_H

struct ssl_buffer {
	
	size_t				tamanno;
	gchar*				buffer;
	struct ssl_buffer*	next;
	struct ssl_buffer*	previous;
	guint 				write_tries;
};

struct queue {
	
	struct ssl_buffer* first;
	struct ssl_buffer* just_sended;
	struct ssl_buffer* last;
};

typedef struct {
	
	guint secuence_number;
	gboolean mark_destroy;
	guint ref_count;

    GIOChannel** Channels_array;		// [0] - client_channel         Este es el channel con el que se conecta el cliente
										// [1] - internal_ssl_channel   Este es el channel para la conexión con el servidor openssl interno
										// [2] - external_ssl_channel	Este es el channel con el que nos conectamos con el servidor real.
    
    
    guint* arreglo_source_ids;			// [0] - client_channel_sd;
										// [1] - internal_ssl_channel_sd;
										// [2] - external_ssl_channel_sd;
										// [3] - timeout_SNI_sd;
										// [4] - timeout_external_ssl_sd;
										// [5] - timer_output_client_channel;
										// [6] - timer_output_internal_channel;
	
    
    gchar peer_ip[16];
    unsigned short int peer_port;
    gchar sock_ip[16];
    gchar* key;						// Esta es una replica de la llave con la que se introdujo remote ip en la ghashtable ssl_connected_tab
									// en su momento.
    gchar* remote_ip;				// Recordar que esto es un puntero a una cadena que se creó en memoria en otra función y que 
									// está también en una ghashtable (ssl_connected_tab) de la cual hay que sacar cuando se elimine
									// la estructura ssl_connection.
    gchar* hw;
    
    
    unsigned char capture_status;	// 0 = Se acaba de comenzar el proceso.
									// 1 = Esperando por la llegada del SNI completo.
									// 2 = Conectándose con el servidor real.
									// 3 = SSL handshaking con el servidor real. 
									// 4 = Extrayendo los datos del certificado real.
									// 5 = Creando el certificado propio.
									// 6 = Conectándose con el servidor openssl interno.
									// 7 = Ya se está conectado con el servidor openssl interno, atendiendo a las colas.
	char *SNI;
	
	struct sockaddr_in real_ssl_server_addr;
	struct sockaddr_in internal_openssl_server_addr;
	char *server_certificate;
	SSL  *real_server_ssl;
	X509 *real_server_certificate;
	int connect_atemp;
	
	struct queue* ssl_queue;
	struct queue* ssl_queue_r;
	
} ssl_connection;

ssl_connection* ssl_connection_new(GIOChannel* channel,guint secuence_number);
void destroy_ssl_conn(ssl_connection* s);

char *parse_tls_header(const char *, int);
char *parse_SNI(const char *, int);
int initialize_openSSL();
int connect_to_real_server(ssl_connection* s);
gboolean handle_ssl_connect( GIOChannel *channel, GIOCondition cond, ssl_connection* s );
gboolean time_out_ssl_handshake(ssl_connection* s);
X509 *ssl_extract_certificado(ssl_connection* s);
void create_own_certificate(ssl_connection* s);
int SSL_iniciar_handshake(ssl_connection* s);
void set_certificate(ssl_connection* s);

int connect_to_internal_openssl(ssl_connection *s);
gboolean timer_output_client_channel(ssl_connection* s);
gboolean handle_openssl_internal( GIOChannel *channel, GIOCondition cond, ssl_connection *s);
void llenar_first_buffer(ssl_connection *s,gchar* buf,guint n);
int checkSNI(ssl_connection* s);
gboolean time_out_SNI(ssl_connection* s);
gboolean timer_output_internal_channel(ssl_connection* s);
gchar* get_certificate(ssl_connection* s);

char* arp_get(gchar* ip_add);

void insert_in_queue(struct queue* the_queue,struct ssl_buffer* buffer_to_include);
void inicialize_queue(struct queue* the_queue,gchar* buf,guint n);
void remove_buffer(struct ssl_buffer* buffer);
void delete_queue(struct queue* the_queue);

#endif
