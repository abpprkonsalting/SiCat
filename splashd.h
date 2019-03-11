# include <glib.h>
# include <glib/gstdio.h>
# include <stdio.h>
# include <string.h>
# include <time.h>
# include <netinet/in.h>
# include <sys/socket.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <signal.h>
# include <fcntl.h>
# include <unistd.h>
# include <syslog.h>
# include <stdlib.h>
# include <getopt.h>
# include <stdarg.h>

# include "gateway.h"

# include <libnetfilter_queue/libnetfilter_queue.h>
//#include <libnetfilter_queue/linux_nfnetlink_queue.h>
# include <linux/netfilter.h>

# include "tls/tls.h"

struct nfq_handle
{
         struct nfnl_handle *nfnlh;
         struct nfnl_subsys_handle *nfnlssh;
         struct nfq_q_handle *qh_list;
};

struct nfq_q_handle
 {
         struct nfq_q_handle *next;
        struct nfq_handle *h;
         u_int16_t id;

         nfq_callback *cb;
         void *data;
 };

 struct nfq_data {
         struct nfattr **data;
 };

/*struct nfq_handle* http_queue_handle;
struct nfq_q_handle* http_q_queue_handle;

struct nfq_handle* http_input_queue_handle;
struct nfq_q_handle* http_input_q_queue_handle;

struct nfq_handle* ssl_queue_handle;
struct nfq_q_handle* ssl_q_queue_handle;*/

struct nfq_iphdr
{

#if defined(__LITTLE_ENDIAN_BITFIELD)

	uint8_t ihl:4,
	version:4;
	
#elif defined (__BIG_ENDIAN_BITFIELD)

	uint8_t version:4,
	ihl:4;

#endif

uint8_t tos;
uint16_t tot_len;
uint16_t id;
uint16_t frag_off;
uint8_t ttl;
uint8_t protocol;
uint16_t check;
uint32_t saddr;
uint32_t daddr;
};

struct nfq_tcphdr
{
uint16_t source;
uint16_t dest;
uint32_t seq;
uint32_t ack_seq;

#if defined(__LITTLE_ENDIAN_BITFIELD)

	uint16_t res1:4,
	doff:4,
	fin:1,
	syn:1,
	rst:1,
	psh:1,
	ack:1,
	urg:1,
	ece:1,
	cwr:1;

#elif defined(__BIG_ENDIAN_BITFIELD)

	uint16_t doff:4,
	res1:4,
	cwr:1,
	ece:1,
	urg:1,
	ack:1,
	psh:1,
	rst:1,
	syn:1,
	fin:1;

#endif

uint16_t window;
uint16_t check;
uint16_t urg_ptr;
};

struct nfq_udphdr
{
uint16_t source;
uint16_t dest;
uint16_t len;
uint16_t check;
};

/************************************************************ Global variables ************************************************************/
extern GHashTable* peer_tab;
GHashTable* ssl_connected_tab;
GHashTable* ssl_certificates_tab;
static int exit_signal = 0;
static FILE* pid_file = NULL;
gchar* macAddressFrom; 
class comm_interface* wsk_comm_interface;
gchar* table;
FILE * log_fd;
gchar* datalnet_IP;
struct hs_array_t* hs_array;

guint ssl_connections_secuence_numbers;
jmp_buf state;
int test_var;	// This variable must be global because when the function destroy_ssl_conn fails there should be no internal variables defined
				// for the purpouse of not letting them hanging. (?)

/************************************************************ Function declarations ********************************************************/

gboolean show_socket_pairs(gchar* function_name, http_request *h);
FILE * initialize_log (void);
char* peer_arp_dns(gchar* ip_add);
int initialize_queue(unsigned int queue_number,int (*nfq_callback)(struct nfq_q_handle *qh,struct nfgenmsg *nfmsg,struct nfq_data *nfad, void *data));
gboolean handle_queue( GIOChannel *channel, GIOCondition cond, struct nfq_handle* queue_handle);
