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

enum demo_protocols {

	PROTOCOL_AUTHENTICATION,
	/* always last */
	DEMO_PROTOCOL_COUNT
};

static int 
callback_authentication(struct libwebsocket_context * this, struct libwebsocket *wsi, enum libwebsocket_callback_reasons reason, 
			void *user, void *in, size_t len);

/* list of supported protocols and callbacks  
static struct libwebsocket_protocols protocols[] = { 
	{ 
		"authentication_protocol",
		callback_authentication,
		0, 

	}, 
	{ /* end of list 
		NULL, 
		NULL, 
		0 
	}
};*/
