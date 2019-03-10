# include <glib.h>
# include <stdio.h>
# include <string.h>
# include <time.h>
# include <libwebsockets.h>
//# include <private-libwebsockets.h>

# include "gateway.h"

#ifndef MFRAME
#define MFRAME 1
#endif

class files_array {

	unsigned int cant;
	GIOChannel** items;
	
	public:
	
	files_array();
	~files_array();
	
	void add_file(int fd);
	void remove_chann(GIOChannel *channel);
	GIOChannel* get_item(int fd);
	
};

enum STATUSES {
	WSK_DISCONNECTED,
	WSK_WAITING_CONFIRM,
	WSK_CLIENT_ESTABLISHED,
	WSK_ERROR,
	WSK_CLOSED,
	WSK_IDDLE
};

void parse_status(int status, char* status_char);

int callback_authentication(struct libwebsocket_context * thi, struct libwebsocket *wsi, enum libwebsocket_callback_reasons reason,
			void *user, void *in, size_t len);

gboolean call_libwebsocket_service(void* dummy);

struct data {

	unsigned int size;
	char* binaries;

};

struct item {
	
	char* nombre;
	char* valor;
};

struct params {

	unsigned int cant;
	struct item** items;
};

class m_frame {

	public:
	unsigned int Version;
	unsigned int Type;
	unsigned int Command;
	unsigned int FrameCount;
	unsigned int AckCount;
	unsigned int BodyFrameSize;
	char FromDeviceId[40];
	char ToDeviceId[40];

	unsigned int cant;
	struct params* parameters;

	// other members

	//bool readed;
	//unsigned char* m_frame_as_message;

	public:

	m_frame(char* message, unsigned int m_size, bool* correct);
	//m_frame(char* comando, struct params* parameters_in, struct data* datos_in, bool* correct);
	~m_frame();

	unsigned short int get_index();
	//unsigned short int get_index_ack();
	//unsigned short int get_body_size();
	//char* get_frame_type();
	//char* get_command_name();
	//struct params* get_parameters();
	//struct data* get_data();
	//bool mark_readed();
	//bool is_readed();
	//unsigned char* as_message();
	//char* print();
	
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
	void run(struct libwebsocket *wsi,enum STATUSES wsk_status);
	unsigned short int get_count();

};

class comm_interface {

	struct libwebsocket_context* context;
	struct libwebsocket* wsi;
	bool init;
	
	time_t wsk_time_out;
	time_t wsk_last_access_time;
	time_t wsk_keep_alive;
	
	enum STATUSES wsk_status;
	
	struct libwebsocket_protocols protocols[2];
	
	void wsk_create_context(void);
	void wsk_client_connect (void);
	
	public:
	
	class received_messages_queu* reception_queu;
	class send_messages_queu* sender_queu;

	comm_interface();
	~comm_interface();

	struct libwebsocket_context* get_context();
	struct libwebsocket* get_wsi();
	time_t get_last_access_time();
	void set_last_access_time();
	time_t get_wsk_time_out();
	time_t get_wsk_keep_alive();

	void wsk_set_status(enum STATUSES status);
	enum STATUSES get_status();
	void reset();
	bool is_init();
	void clear_init();
	void set_init();
	
	int wsk_send_command(char* comando, struct params* parameters_in, struct data* datos_in);
	
	
};

struct mi_struct{
	
	bool encontrado;
	class m_frame* trama;
};




