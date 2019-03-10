# include <syslog.h>
# include <libwebsockets.h>
# include "gateway.h"
# include "config.h"

#include <stdlib.h> 
#include <getopt.h> 
#include <stdarg.h> 

# include <libwebsockets.h>

static int 
callback_authentication(struct libwebsocket_context * this, struct libwebsocket *wsi, enum libwebsocket_callback_reasons reason, 
			void *user, void *in, size_t len) {
 
	switch (reason) { 
		case LWS_CALLBACK_CLOSED: 
			fprintf(stderr, "LWS_CALLBACK_CLOSED\n"); 
			was_closed = 1; 
			break; 

		case LWS_CALLBACK_CLIENT_RECEIVE:
			((char *)in)[len] = '\0';
			fprintf(stderr, "rx %d '%s'\n", (int)len, (char *)in);
			break; 

	/* because we are protocols[0] ... */ 

		case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:
			if ((strcmp(in, "deflate-stream") == 0) && deny_deflate) {
				 fprintf(stderr, "denied deflate-stream extension\n"); 
				return 1;
			}
			if ((strcmp(in, "x-google-mux") == 0) && deny_mux) { 
				fprintf(stderr, "denied x-google-mux extension\n");
				return 1;
			} 
			break; 
		default: 
			break; 
	}

	return 0;
}