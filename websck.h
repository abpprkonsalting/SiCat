# include <glib.h>
# include <stdio.h>
# include <netinet/in.h>
# include <sys/socket.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <signal.h>
# include <string.h>
# include <time.h>
# include <stdio.h>
# include <fcntl.h>
# include <unistd.h>
# include <libwebsockets.h>

//# include "gateway.h"
# include "config.h"

enum demo_protocols {

	PROTOCOL_AUTHENTICATION,
	/* always last */
	DEMO_PROTOCOL_COUNT
};

int callback_authentication(struct libwebsocket_context* thi, struct libwebsocket* wsi, enum libwebsocket_callback_reasons reason, 
			void* user, void* in, size_t len);

 /*list of supported protocols and callbacks  */
static struct libwebsocket_protocols protocols[] = { 
	{ 
		"authentication_protocol",
		callback_authentication,
		0,
		4096, 

	}, 
	{ /* end of list */
		NULL, 
		NULL, 
		0,
		0
	}
};

struct libwebsocket_context* wsk_create_context(void);

struct libwebsocket* wsk_client_connect (struct libwebsocket_context* context, time_t* connection_time);



