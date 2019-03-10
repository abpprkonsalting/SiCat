# include <glib.h>
# include <ctype.h>
# include <time.h>
# include <libwebsockets.h>
# include "conf.h"
# include "util.h"
# include "defaults.h"

/*** Global config settings ***/
GHashTable *nocat_conf = NULL;

/********** Conf stuff **********/

// NOTE: parse_conf_line destroys line!!!
GHashTable *parse_conf_line( GHashTable *out, gchar *line ) {
    gchar *key, *val;

    g_assert( out  != NULL );
    g_assert( line != NULL );

    // Format is: \s*(?:#.*|(\w+)\s+(.*)\s*)
    key = g_strchug(line);	    // Strip leading whitespace.
    if (!isalpha( *key )) return out;	    // Skip comments.
    for (val = key; isident(*val); val++); 
					// Find the end of the key.
    *(val++) = '\0';		    // Mark it. 
    g_strstrip(val);		    // The value extends to EOL.
    g_hash_set( out, key, val );
    return out;
}

GHashTable *parse_conf_string( const gchar *in ) {
    gchar **lines;
    guint i;
    GHashTable *out = g_hash_new();

    lines = g_strsplit( in, "\n", 0 );
    for ( i = 1; lines[i] != NULL; i++ )
	parse_conf_line( out, lines[i] );

    g_strfreev( lines );
    return out;
}

GHashTable *set_conf_defaults( GHashTable *conf, struct conf_t *def ) {
    guint i;
    time_t now;
    
    for (i = 0; def[i].param != NULL; i++)
	if (g_hash_table_lookup(conf, def[i].param) == NULL) {
	    if (def[i].value == NULL)
		g_error("Required config param missing: %s", def[i].param);
	    else
		g_hash_set(conf, def[i].param, def[i].value);
	}

    time(&now);
    g_hash_set( conf, "GatewayStartTime", ctime(&now) );

    return conf; 
}

void set_network_defaults( GHashTable *conf ) {
    gchar *intdev, *extdev, *localnet, *mac;

    extdev = (gchar*) g_hash_table_lookup(conf, "ExternalDevice");
    if (extdev == NULL) {
	extdev = detect_network_device(NULL); 
	if (extdev) {
	    //g_message( "Autodetected ExternalDevice %s", extdev );
	    lwsl_info("Autodetected ExternalDevice %s", extdev);
	    g_hash_table_insert( conf, (gpointer)"ExternalDevice", (gpointer)extdev );
	} else
	    //g_error( "No ExternalDevice detected!" );
	    lwsl_err("No ExternalDevice detected!");
    }
    
    intdev = (gchar*)g_hash_table_lookup(conf, "InternalDevice");
    if (intdev == NULL) {
	intdev = detect_network_device(extdev); 
	if (intdev) {
	    //g_message( "Autodetected InternalDevice %s", intdev );
	    lwsl_info("Autodetected InternalDevice %s", intdev);
	    g_hash_table_insert( conf, (gpointer)"InternalDevice", (gpointer)intdev );
	} else
	    //g_error( "No InternalDevice detected!" );
	    lwsl_err("No ExternalDevice detected!");
    }
    
    if (g_hash_table_lookup(conf, "LocalNetwork") == NULL) {
	localnet = get_network_address(intdev);
	if (localnet) {
	    //g_message( "Autodetected LocalNetwork %s", localnet );
	    lwsl_info("Autodetected LocalNetwork %s", localnet);
	    g_hash_table_insert( conf, (gpointer)"LocalNetwork", (gpointer)localnet );
	} else
	    //g_error( "No LocalNetwork detected!" );
	    lwsl_err("No LocalNetwork detected!");
    }
    
    if (g_hash_table_lookup(conf, "NodeID") == NULL) {
	mac = get_mac_address(intdev);
	if (mac) {
	    g_hash_table_insert(conf, (gpointer)"NodeID", (gpointer)mac);
	    //g_message( "My node ID is %s (%s)", mac, intdev);
	    lwsl_info("My node ID is %s (%s)", mac, intdev);
	} else
	    //g_warning( "No NodeID discernable from MAC address!" );
	    lwsl_warn("No NodeID discernable from MAC address!");
    }
}

GHashTable *read_conf_file( const gchar *path ) {

    gchar *file = load_file(path);

    if (file == NULL) 
	return NULL;
    
    if (nocat_conf != NULL) {
	g_warning("Reloading configuration from %s!", path);
	g_free(nocat_conf);
    }

    nocat_conf = parse_conf_string( file );
    set_conf_defaults( nocat_conf, default_conf );

    //g_message( "Read %d config items from %s", g_hash_table_size(nocat_conf), path ); 
    g_free( file );
    return nocat_conf;
}

/*Modifications added by abp*/
gchar *conf_string( GHashTable *conf, const gchar *key ){

	/* abp: The line order was changed because it does not feels right to execute g_hash_table_lookup before asserting key and conf
	gchar *val = g_hash_table_lookup( conf, key );
	g_assert( key != NULL );
	g_assert( conf != NULL );*/

	gchar* val;
	
	//g_assert( key != NULL);
	//g_assert( conf != NULL );

	val = (gchar*) g_hash_table_lookup( conf, key );/* added by abp*/
	if (val == NULL) g_warning("Missing required configuration directive '%s'", key);
	return val;
}

/*Modifications added by abp*/
glong conf_int( GHashTable *conf, const gchar *key ) {

	/* abp: The line order was changed because it does not feels right to execute g_hash_table_lookup before assertin key,
		besides it was added the assertion of conf, that is missing
	gchar *val = g_hash_table_lookup( conf, key );*/

	gchar *val;

	gchar *err;
	glong vint;

	g_assert( key != NULL );
	g_assert( conf != NULL );/* added by abp*/

	val = (gchar*) g_hash_table_lookup( conf, key );/* added by abp*/
	if (val == NULL) g_warning("Missing required configuration directive '%s'", key);

	vint = strtol( val, &err, 10 );
	if ( err != NULL && *err != '\0' ) g_warning("Invalid numeric configuration directive '%s': %s", key, val );

	return vint;
}

/*Modifications added by abp*/
gdouble conf_float( GHashTable *conf, const gchar *key ) {

	/* abp: The line order was changed because it does not feels right to execute g_hash_table_lookup before assertin key,
		besides it was added the assertion of conf, that is missing
	gchar *val = g_hash_table_lookup( conf, key );*/

	gchar *val;

	gchar *err;
	gdouble vdbl;

	g_assert( key != NULL );
	g_assert( conf != NULL );/* added by abp*/

	val = (gchar*) g_hash_table_lookup( conf, key );/* added by abp*/
	if (val == NULL) g_warning("Missing required configuration directive '%s'", key);

	vdbl = strtod( val, &err );
	if ( err != NULL && *err != '\0' )
	g_warning("Invalid numeric configuration directive '%s': %s", key, val );
	return vdbl;
}
