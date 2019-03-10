# include <stdio.h>
//# include "conf.h"
# include "config.h"
# include "mime.h"

struct conf_t default_conf[] = {
	
    // Gateway server networking values.
    { (gchar*)"GatewayAddr",	(gchar*)"0.0.0.0" },
    { (gchar*)"GatewayPort",	(gchar*)"5280" },
    { (gchar*)"ListenQueue",	(gchar*)"20" },

    /*This is now all auto-detected in set_conf_defaults()
    //{ (gchar*)"ExternalDevice",	(gchar*)"0" },
    //{ (gchar*)"InternalDevice",	(gchar*)"0" },
    //{ (gchar*)"LocalNetwork",	(gchar*)"0" },*/

    { (gchar*)"FirewallPath",	(gchar*)NC_FIREWALL_PATH },
    { (gchar*)"ResetCmd",	(gchar*)"$FirewallPath/initialize.fw" },
    { (gchar*)"PermitCmd",	(gchar*)"$FirewallPath/access.fw permit $MAC $IP $Class" },
    { (gchar*)"DenyCmd",	(gchar*)"$FirewallPath/access.fw deny $MAC $IP $Class" },
    { (gchar*)"InitCmd",	(gchar*)"$FirewallPath/reset.fw" },

    { (gchar*)"AuthServiceAddr", (gchar*)"www.datalnet.com" },
    { (gchar*)"AuthServiceURL", (gchar*)"http://www.datalnet.com/SocialNetwork" },
    { (gchar*)"LogoutURL",	(gchar*)"http://www.datalnet.com/logout.html" },
    { (gchar*)"HomePage",	(gchar*)"http://www.datalnet.com" },
    
    { (gchar*)"LoginTimeout",	 (gchar*)"1200" },
    { (gchar*)"LoginGrace",	 (gchar*)"180" },

    //  Where to look for form templates?
    { (gchar*)"DocumentRoot",	 (gchar*)NC_DOCUMENT_ROOT },

    //  Default log level.
    { (gchar*)"Verbosity",	(gchar*)"5" },
    { (gchar*)"LogFacility",	(gchar*)"syslog" },
    { (gchar*)"SyslogIdent",	(gchar*)"SiCat" },

	// Websocket defaults
	{ (gchar*)"wsk_server_address",	(gchar*)"www.datalnet.com"},
	{ (gchar*)"wsk_server_port",	(gchar*)"80"},
	{ (gchar*)"wsk_path_on_server",	(gchar*)"/api/ServiceLine"},
	{ (gchar*)"wsk_server_hostname",	(gchar*)"www.datalnet.com"},
	{ (gchar*)"wsk_origin_name",	(gchar*)"localhost"},
	{ (gchar*)"wsk_protocol",	(gchar*)"0"},
	{ (gchar*)"wsk_iface",	(gchar*)"NULL"},
	{ (gchar*)"wsk_use_ssl",	(gchar*)"0"},
	{ (gchar*)"ietf_version",	(gchar*)"-1"},
	{ (gchar*)"wsk_time_out",	(gchar*)"600"},
	{ (gchar*)"wsk_keep_alive",	(gchar*)"3600"},
	{ (gchar*)"wsk_log_level", (gchar*)"1"},
	

    // Trailing NULL
    { NULL, NULL }
};

struct mime_type_t mime_types[] = {
    { (gchar*)"hqx", (gchar*)"application/mac-binhex40" },
    { (gchar*)"doc", (gchar*)"application/msword" },
    { (gchar*)"bin", (gchar*)"application/octet-stream" },
    { (gchar*)"class", (gchar*)"application/octet-stream" },
    { (gchar*)"so", (gchar*)"application/octet-stream" },
    { (gchar*)"pdf", (gchar*)"application/pdf" },
    { (gchar*)"ps", (gchar*)"application/postscript" },
    { (gchar*)"ppt", (gchar*)"application/vnd.ms-powerpoint" },
    { (gchar*)"bz2", (gchar*)"application/x-bzip2" },
    { (gchar*)"gz", (gchar*)"application/x-gzip" },
    { (gchar*)"tgz", (gchar*)"application/x-gzip" },
    { (gchar*)"js", (gchar*)"application/x-javascript" },
    { (gchar*)"ogg", (gchar*)"application/x-ogg" },
    { (gchar*)"swf", (gchar*)"application/x-shockwave-flash" },
    { (gchar*)"xhtml", (gchar*)"application/xhtml+xml" },
    { (gchar*)"xht", (gchar*)"application/xhtml+xml" },
    { (gchar*)"zip", (gchar*)"application/zip" },
    { (gchar*)"mid", (gchar*)"audio/midi" },
    { (gchar*)"mp2", (gchar*)"audio/mpeg" },
    { (gchar*)"mp3", (gchar*)"audio/mpeg" },
    { (gchar*)"m3u", (gchar*)"audio/x-mpegurl" },
    { (gchar*)"ra", (gchar*)"audio/x-realaudio" },
    { (gchar*)"bmp", (gchar*)"image/bmp" },
    { (gchar*)"gif", (gchar*)"image/gif" },
    { (gchar*)"jpeg", (gchar*)"image/jpeg" },
    { (gchar*)"jpg", (gchar*)"image/jpeg" },
    { (gchar*)"jpe", (gchar*)"image/jpeg" },
    { (gchar*)"png", (gchar*)"image/png" },
    { (gchar*)"tiff", (gchar*)"image/tiff" },
    { (gchar*)"tif", (gchar*)"image/tiff" },
    { (gchar*)"css", (gchar*)"text/css" },
    { (gchar*)"html", (gchar*)"text/html" },
    { (gchar*)"htm", (gchar*)"text/html" },
    { (gchar*)"asc", (gchar*)"text/plain" },
    { (gchar*)"txt", (gchar*)"text/plain" },
    { (gchar*)"rtx", (gchar*)"text/richtext" },
    { (gchar*)"rtf", (gchar*)"text/rtf" },
    { (gchar*)"xml", (gchar*)"text/xml" },
    { (gchar*)"xsl", (gchar*)"text/xml" },
    { (gchar*)"mpeg", (gchar*)"video/mpeg" },
    { (gchar*)"mpg", (gchar*)"video/mpeg" },
    { (gchar*)"mpe", (gchar*)"video/mpeg" },
    { (gchar*)"qt", (gchar*)"video/quicktime" },
    { (gchar*)"mov", (gchar*)"video/quicktime" },
    { (gchar*)"avi", (gchar*)"video/x-msvideo" },
    { (gchar*)"rmm", (gchar*)"audio/x-pn-realaudio" },
    { (gchar*)"ram", (gchar*)"audio/x-pn-realaudio" },
    { (gchar*)"ra", (gchar*)"audio/vnd.rn-realaudio" },
    { (gchar*)"smi", (gchar*)"application/smil" },
    { (gchar*)"smil", (gchar*)"application/smil" },
    { (gchar*)"rt", (gchar*)"text/vnd.rn-realtext" },
    { (gchar*)"rv", (gchar*)"video/vnd.rn-realvideo" },
    { (gchar*)"rm", (gchar*)"application/vnd.rn-realmedia" },
    { (gchar*)"wav", (gchar*)"audio/wav" },
    { NULL, NULL } };
