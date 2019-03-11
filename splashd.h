# include <glib.h>
#include <glib/gstdio.h>
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
#include <stdlib.h>
#include <getopt.h>
#include <stdarg.h>

# include "gateway.h"
# include "dns.h"

//#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
//#include <libnetfilter_queue/linux_nfnetlink_queue.h>
#include <linux/netfilter.h>


//usr/include/libnetfilter_queue/libnetfilter_queue.h
//usr/include/libnetfilter_queue/
//usr/include/libnetfilter_queue/libnetfilter_queue_ipv6.h
//usr/include/libnetfilter_queue/libnetfilter_queue_tcp.h
//usr/include/libnetfilter_queue/libnetfilter_queue_udp.h
//usr/include/libnetfilter_queue/linux_nfnetlink_queue.h


extern GHashTable* peer_tab;
static int exit_signal = 0;
static FILE* pid_file = NULL;
gchar* macAddressFrom; 
class comm_interface* wsk_comm_interface;
gchar* table;

class h_requests* requests;

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

struct nfq_handle* http_queue_handle;
struct nfq_handle* output_queue_handle;

struct nfq_q_handle* http_q_queue_handle;
struct nfq_q_handle* output_q_queue_handle;

gboolean show_socket_pairs(gchar* function_name, http_request *h);
void peer_arp_dns(gchar* ip_add, gchar* hw_add);
