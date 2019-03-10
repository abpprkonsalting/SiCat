# include <glib.h>
# include <sys/time.h>

# include "conf.h"
# include "util.h"
# include "http.h"

/*** Function prototypes start here ***/
peer *peer_new ( GHashTable *conf, const gchar *ip );
void peer_free ( peer *p );
int peer_permit ( GHashTable *conf, peer *p, http_request* h);
int peer_deny ( GHashTable *conf, peer *p );
gchar *get_peer_token ( peer *p );

/*** Function prototypes start here ***/
int fw_perform( gchar *action, GHashTable *conf, peer *p, http_request* h);
int fw_init ( GHashTable *conf );
gchar *peer_arp( peer *p );
