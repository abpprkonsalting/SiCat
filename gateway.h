//# include "http.h"
# include "firewall.h"

gchar* target_redirect ( http_request *h );
gchar* local_host( http_request *h );
peer *find_peer ( const gchar *ip, gboolean* new_peer );
void accept_peer ( http_request *h );
void remove_peer ( peer *p );
gboolean check_peer_expire ( gchar *ip, peer *p, time_t *now );
void status_page ( http_request *h );
gboolean check_peer(class m_frame* frame);

/*** actually defined in either open.c or passive.c ***/
void initialize_driver( void );
void handle_request( http_request *h );

