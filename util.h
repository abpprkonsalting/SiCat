# include <glib.h>
# include <ctype.h>
# include <string.h>
# include <fcntl.h>
# include <unistd.h>
# include <stdio.h>
# include <stdlib.h>
# include <sys/stat.h>
# include <sys/socket.h>
# include <sys/mman.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <crypt.h>

# ifndef g_debug
# ifdef DEBUG
# define g_debug(format...)     g_log (G_LOG_DOMAIN,       \
                                       G_LOG_LEVEL_DEBUG,  \
                                       format)
# else
# define g_debug(format...)
# endif
# endif

# define isident(x) (isalnum(x) || (x) == '_')

gchar *g_strncpy( gchar *dest, const gchar *src, guint n );
GHashTable *g_hash_new ();
guint g_hash_free (GHashTable *h);
gboolean g_hash_delete(GHashTable * h, const gchar *key);
gboolean g_hash_set(GHashTable *h, const gchar *key, gchar *val);
GHashTable *g_hash_merge( GHashTable *dest, GHashTable *src );
GHashTable *g_hash_dup( GHashTable *src );
GString *g_hash_as_string( GHashTable *h );
gchar *url_decode( const gchar *src );
gchar *url_encode( const gchar *src );
GString *build_url( const gchar *uri, GHashTable *query );
gchar *load_file( const char *path );
gchar *parse_template( gchar *src, GHashTable *data );
gchar *strrand(gchar *dest, int n);
gchar *md5_crypt( const gchar *src, gchar *salt );

/* base64.c */
gchar *base64_decode( const gchar *from );
gchar *base64_encode( const gchar *s, const int length );

/* linux.c */
gchar *get_mac_address( const gchar *dev );
gchar *get_network_address( const gchar *dev );
gchar *detect_network_device( const gchar *exclude );


gboolean get_address_from_name(gchar* name);
