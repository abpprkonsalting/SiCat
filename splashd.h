# include <glib.h>
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

extern GHashTable* peer_tab;
static int exit_signal = 0;
static FILE* pid_file = NULL;
gchar* macAddressFrom; 
class comm_interface* wsk_comm_interface;

class h_requests* requests;

gboolean show_socket_pairs(gchar* function_name, http_request *h);
