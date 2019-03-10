# include "util.h"
# include "config.h"

/********** Hash stuff **********/

gchar *g_strncpy( gchar *dest, const gchar *src, guint n ) {
    strncpy( dest, src, n );
    dest[ n - 1 ] = '\0';
    return dest;
}

GHashTable* g_hash_new (void) {
    return g_hash_table_new( g_str_hash, g_str_equal );
}

static gboolean g_hash_free_each ( gpointer key, gpointer val, gpointer data ) {
    // g_warning("freeing %s (= %s)", key, val);
    if (key != NULL) g_free(key);
    if (val != NULL) g_free(val);
    return TRUE;
}

guint g_hash_free (GHashTable *h) {
    guint n;
    if (h == NULL) return 0;
    n = g_hash_table_foreach_remove( h, g_hash_free_each, NULL );
    g_hash_table_destroy( h );
    return n;
}

gboolean g_hash_delete(GHashTable * h, const gchar *key) {
    gpointer k, v;
    gchar *kk, *vv;

    //g_assert( h   != NULL );
    //g_assert( key != NULL );

    // if (g_hash_table_lookup_extended(h, key, (gpointer *)&k, (gpointer *)&v)) {
    if (g_hash_table_lookup_extended(h, key, &k, &v)) {
		g_hash_table_remove(h, key);
			kk = ((gchar *) k);
			vv = ((gchar *) v);
		if (kk != NULL) g_free(kk);
		if (vv != NULL) g_free(vv);
	return TRUE;
    }
    return FALSE;
}

gboolean g_hash_set(GHashTable *h, const gchar *key, gchar *val) {
    gchar *k, *v;
    gboolean over;

    //g_assert( h   != NULL );
    //g_assert( key != NULL );
    //g_assert( val != NULL );
	
	//g_message("antes del delete %s: %s",key,val);
	
    over = g_hash_delete(h, key);
    k = g_strdup(key);
    v = g_strdup(val);
    
    //g_message("después del delete %s: %s",k,v);
    g_hash_table_insert(h, k, v);
    return over;
}

static void g_hash_dup_each ( gchar *k, gchar *v, GHashTable *dest ) {
	
	g_hash_set( dest, k, v );
}

GHashTable *g_hash_merge( GHashTable *dest, GHashTable *src ) {
    g_hash_table_foreach( src, (GHFunc) g_hash_dup_each, dest );
    //g_message("returning from g_hash_merge");
    return dest;
}

GHashTable *g_hash_dup( GHashTable *src ) {
	//g_message("entré en g_hash_dup");
    GHashTable *dest = g_hash_new();
    return g_hash_merge( dest, src );
}

static void g_hash_as_string_each( gchar *k, gchar *v, GString *dest ) {
	
    g_string_sprintfa( dest, "%s=%s\n", k, v );
}

GString* g_hash_as_string( GHashTable *h ) {
	
    GString *dest = g_string_new("");
    g_assert( h != NULL );
    g_hash_table_foreach( h, (GHFunc) g_hash_as_string_each, dest );
    return dest;
}

/********** URL encoding **********/

static int fromhex ( char digit ) {
    char d = toupper(digit);
    if (!isxdigit(digit)) return 0;
    if (isdigit(d)) {
	return d - '0';
    } else {
	return (int) ( d - 'A' ) + 10;
    }
}

gchar *url_decode( const gchar *src ) {
    gchar *dest, *dest0;
    int n;

    n = strlen(src) + 1;
    dest = dest0 = g_new0(gchar, n);

    for (; *src != '\0' && n >= 0; ++dest, ++src, --n )
	if ( *src == '%' && n > 2 )  {
	    *dest  = fromhex( *(++src) ) * 0x10;
	    *dest += fromhex( *(++src) );
	    n -= 2;
	} else if ( *src == '+' ) 
	    *dest = ' ';
	else
	    *dest = *src;

    *dest = '\0';
    return dest0; // g_renew( gchar, dest0, ++n );
}

gchar *url_encode( const gchar *src ) {
    char *dest, *dest0;
    int n = strlen(src) + 1;
   
    dest = dest0 = g_new0(gchar, n * 3);

    for (; *src != '\0' && n >= 0; src++, dest++, n--) {
	// g_message( "src: %s dest: %s n: %d", src, dest0, n );
	if ( isalnum(*src) || strchr("./-_", *src) )
	    *dest = *src;
	else if ( *src == ' ' )
	    *dest = '+';
	else {
	    sprintf( dest, "%%%02X", (int) *src & 0xFF );
	    dest += 2;
	}
    }

    *dest = '\0'; 
    return dest0; // g_renew( gchar, dest0, ++n );
}

static void build_url_each( gchar *k, gchar *v, GString *dest ) {
    gchar *val = url_encode( v );
    g_string_sprintfa( dest, "%s=%s&", k, val );
    g_free( val );
}

GString *build_url( const gchar *uri, GHashTable *query ) {
	
    GString *dest = g_string_new( uri );
    //g_assert( query != NULL );

    g_string_append( dest, "?" );
    g_hash_table_foreach( query, (GHFunc) build_url_each, dest );
    g_string_erase( dest, dest->len - 1, 1 );
    
    return dest;
}


/********** I/O stuff **********/

gchar *load_file( const char *path ) {
    gchar *file;
    struct stat s;
    void *data;
    int fd, r;

    g_assert( path != NULL );

    fd = open( path, O_RDONLY );
    if ( fd == -1 ) {
		g_warning( "Can't open %s: %m", path );
		return NULL;
    }

    r = fstat( fd, &s );
    //g_assert( r == 0 );

    data = mmap( NULL, s.st_size, PROT_READ, MAP_SHARED, fd, 0 );
    //g_assert( data != MAP_FAILED );

    file = g_strndup( (gchar*)data, s.st_size );
    //g_assert( file != NULL );

    r = munmap( data, s.st_size );
    //g_assert( r == 0 );

    r = close(fd);
    //g_assert( r == 0 );

    return file;
}


gchar *parse_template( gchar *src, GHashTable *data1 ) {
	
    GString *dest = g_string_sized_new(strlen(src));
    guint n;
    gchar *var, *val;

    for (; *src != '\0'; src++) {
    	
		// Find the text chunk up to the next $, 
		// and append it to the buffer.
		
		n = strcspn( src, "$" );
		if (n) {
			g_string_sprintfa( dest, "%.*s", n, src );
			src += n;
			if ( *src == '\0' )
			break;
		}
			//g_message( "voy por 3.1");
		// If the immediately following char is alphabetical...
		if (isalpha(*( src + 1 ))) {
			// Find the identifier following the $
			for (n = 2; isident(src[n]); n++);

			// Having found it, copy the variable name out
			// and get the corresponding value.
			var = g_strndup( src + 1, --n );
			val = (gchar*) g_hash_table_lookup( data1, var );
			if (val)	g_string_append(dest, val);
			g_free(var);

			src += n;
				//g_message( "voy por 3.2");
		} 
		else {
			// Otherwise save the $
			g_string_append(dest, "$");
				//g_message( "voy por 3.3");
		}
    }
    
    //val = g_renew( gchar, dest->str, strlen(dest->str) + 1 );
    
    val = g_try_new0 (gchar, strlen(dest->str) + 1);
    if (val != NULL){
    	
    	memcpy(val,dest->str,strlen(dest->str));
	}
	else g_message ("util.cc parse_template: could not allocate space for return value");
    
    	//g_message( "voy por 3.4");
    g_string_free( dest, FALSE );
    //g_message( "voy por 3");
    return val;
}

/**** crypt-type functions *********/

//# ifdef HAVE_LIBCRYPT

static char salt_chars[] = 
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./";

gchar *strrand (gchar *dest, int n) {
    int i;
    for (i = 0; i < n; i++)
	dest[i] = salt_chars[ rand() % sizeof(salt_chars) ];
    dest[n] = '\0';
    return dest; 
}

gchar *md5_crypt( const gchar *src, gchar *salt ) {
    gchar salt2[12], *hash;

    if (salt == NULL) {
	strcpy( salt2, "$1$" );
	strrand( salt2 + 3, 8 );
    } else {
	strncpy( salt2, salt, 11 );
    }
    salt2[11] = '\0';
    
    hash = g_strdup( crypt(src, salt2) );
	//hash = NULL;
    return hash;
}

//# endif /* HAVE_LIBCRYPT */


gboolean get_address_from_name(gchar* name){
	
	char *first, *second, *third, *temp;
	gboolean is_IP = TRUE;
	
	//struct hostent * host_info;
	
	//Chequear que la variable no sea ya una ip
	
	first = strtok ((char *)name, (const char *)".");
	
	if (first != NULL){
		
		if (strcspn(first, (const char *)"0123456789") == 0 ){
			
			second = strtok (NULL, (const char *)".");
			
			if (second != NULL){
				
				if (strcspn(second, (const char *)"0123456789") == 0 ){
					
					third = strtok (NULL, (const char *)".");
					
					if (strcspn(third, (const char *)"0123456789") == 0 ){
						
						
					}
				}
			}
		}
		else {
			// Hay un caracter no numérico en el primer token, por lo tanto esto no es una dirección
			// IP
			
			is_IP = FALSE;
			
		}		
	}
	else {
		// This is the else of the search for the first token. As not finding a first dot means that
		// there is not dots at all in the name passed as argument to the function this could not be
		// an ip address so we try to solve the address.
		
		is_IP = FALSE;
	}
	
}
