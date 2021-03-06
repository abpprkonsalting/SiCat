//# include "http.h"
# include "firewall.h"
# include "websck.h"

gchar* target_redirect ( http_request *h);
gchar* local_host( http_request *h );
peer *find_peer (http_request *h);
void accept_peer ( http_request *h );
void remove_peer ( peer *p );
gboolean check_peer_expire ( gchar *ip, peer *p, time_t *now );
void status_page ( http_request *h );
gboolean check_peer(class m_frame* frame);

/*** actually defined in either open.c or passive.c ***/
int handle_request( http_request *h );
void splash_peer ( http_request *h );
void punish_peer ( http_request *h, peer* p, gchar* original_url);

