# include <glib.h>
# include <sys/time.h>

# include "conf.h"
# include "util.h"
# include "http.h"

extern GHashTable *nocat_conf;

/*** Function prototypes start here ***/
peer *peer_new ( GHashTable* conf, http_request *h );
void peer_free ( peer *p );
int peer_permit ( GHashTable *conf, peer *p);
int peer_deny ( GHashTable *conf, peer *p );
gchar *get_peer_token ( peer *p );
void redirecciona_http (http_request *h, peer* p );

/*** Function prototypes start here ***/
int fw_perform( gchar *action, GHashTable *conf, peer *p);
int fw_init ( GHashTable *conf );
gchar *peer_arp( peer *p );
int fw_resettable (GHashTable *conf);
