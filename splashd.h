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
# include <syslog.h>
# include <libwebsockets.h>
# include "gateway.h"

#include <stdlib.h>
#include <getopt.h>
#include <stdarg.h>

#ifndef MFRAME
#define MFRAME 1
#endif

extern GHashTable* peer_tab;
static int exit_signal = 0;
static FILE* pid_file = NULL;
class comm_interface* wsk_comm_interface;
bool wsk_stablished;
bool wsk_closed;
bool wsk_wants_close;

//static int deny_deflate;
//static int deny_mux;

struct libwebsocket_context* wsk_create_context(void);
struct libwebsocket* wsk_client_connect (struct libwebsocket_context* context, time_t* connection_time);
gboolean check_wsk_timeout(struct libwebsocket* wsi);
int callback_authentication(struct libwebsocket_context * thi, struct libwebsocket *wsi, enum libwebsocket_callback_reasons reason,
			void *user, void *in, size_t len);

enum demo_protocols {

	PROTOCOL_AUTHENTICATION,
	/* always last */
	DEMO_PROTOCOL_COUNT
};

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

struct data {

	unsigned int size;
	char* binaries;

};

struct params {

	unsigned int cant;
	char** values;
};

class m_frame {

	// frame header

	unsigned short int m_frame_index;
	unsigned short int m_frame_index_ack;
	unsigned short int body_size;
	char frame_type[2];

	// frame body

	char* command_name;
	struct params* parameters;
	struct data* datos;

	// other members

	bool readed;
	unsigned char* m_frame_as_message;

	public:

	m_frame(char* message, unsigned int m_size, bool* correct);
	m_frame(char* comando, struct params* parameters_in, struct data* datos_in, bool* correct);
	~m_frame();

	unsigned short int get_index();
	unsigned short int get_index_ack();
	unsigned short int get_body_size();
	char* get_frame_type();
	char* get_command_name();
	struct params* get_parameters();
	struct data* get_data();
	bool mark_readed();
	bool is_readed();
	unsigned char* as_message();
	char* print();
	
};

class received_messages_queu {

	// received_messages_queu class members

	unsigned short int count;
	struct m_frame** ptr_frames;

	// received_messages_queu class methods

	public:

	received_messages_queu();
	~received_messages_queu();
	unsigned short int get_count();
	bool receive_frame(char* message,size_t message_size);
	bool delete_frame(unsigned int m_frame_index);


};

class send_messages_queu {

	// send_messages_queu class members

	unsigned short int count;
	struct m_frame** ptr_frames;

	// send_messages_queu class methods

	public:

	send_messages_queu();
	~send_messages_queu();

	bool add_frame(char* comando, struct params* parameters_in, struct data* datos_in);
	bool delete_frame(unsigned int m_frame_index);
	void run(struct libwebsocket *wsi);

};

class comm_interface {

	struct libwebsocket_context* context;
	struct libwebsocket* wsi_dumb;
	time_t wsk_time_out;
	time_t wsk_initial_time;


	public:

	class received_messages_queu* reception_queu;
	class send_messages_queu* sender_queu;

	comm_interface(bool* error);
	~comm_interface();

	struct libwebsocket_context* get_context();
	time_t get_wsk_initial_time();
	time_t get_wsk_time_out();
	bool close_wsk(struct libwebsocket* wsi);
	void mod_wsk_initial_time();

};

gboolean show_socket_pairs(gchar* function_name, http_request *h);
