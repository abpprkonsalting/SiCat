# include <stdio.h>
# include <errno.h>
# include <string.h>
# include <sys/stat.h>
# include <sys/sendfile.h>
# include <sys/ioctl.h>
# include <sys/socket.h>
# include <net/if.h>
# include <netinet/in.h>

# include "http.h"
# include "firewall.h"
# include "util.h"

ssize_t http_sendfile ( http_request *h, int in_fd );
gchar *peer_arp( peer *p );
gchar *get_mac_address (const gchar *dev);
gchar *get_network_address (const gchar *dev);
gchar *detect_network_device ( const gchar *exclude );
