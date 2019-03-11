#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>	//printf
#include <string.h>	//strlen
#include <stdlib.h>	//malloc
#include <sys/socket.h>	//you know what this is for
#include <arpa/inet.h>	//inet_addr , inet_ntoa , ntohs etc
#include <netinet/in.h>
#include <unistd.h>	//getpid
#include <gio/gio.h>
#include "conf.h"
#include "util.h"
#include "http.h"
#include "websck.h"

extern GHashTable *nocat_conf;

//Types of DNS resource records :)
#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server

struct nfq_iphdr
{

#if defined(__LITTLE_ENDIAN_BITFIELD)

	uint8_t ihl:4,
	version:4;
	
#elif defined (__BIG_ENDIAN_BITFIELD)

	uint8_t version:4,
	ihl:4;

#endif

uint8_t tos;
uint16_t tot_len;
uint16_t id;
uint16_t frag_off;
uint8_t ttl;
uint8_t protocol;
uint16_t check;
uint32_t saddr;
uint32_t daddr;
};

struct nfq_tcphdr
{
uint16_t source;
uint16_t dest;
uint32_t seq;
uint32_t ack_seq;

#if defined(__LITTLE_ENDIAN_BITFIELD)

	uint16_t res1:4,
	doff:4,
	fin:1,
	syn:1,
	rst:1,
	psh:1,
	ack:1,
	urg:1,
	ece:1,
	cwr:1;

#elif defined(__BIG_ENDIAN_BITFIELD)

	uint16_t doff:4,
	res1:4,
	cwr:1,
	ece:1,
	urg:1,
	ack:1,
	psh:1,
	rst:1,
	syn:1,
	fin:1;

#endif

uint16_t window;
uint16_t check;
uint16_t urg_ptr;
};

struct nfq_udphdr
{
uint16_t source;
uint16_t dest;
uint16_t len;
uint16_t check;
};

//DNS header structure
struct DNS_HEADER
{
    unsigned short id; // identification number
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

//Constant sized fields of query structure
struct QUESTION
{
	unsigned short qtype;
	unsigned short qclass;
};

//Query Structure
struct QUERY
{
    unsigned char *name;
    unsigned short qtype;
    unsigned short qclass;
};

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};

#pragma pack(pop)
//Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};

struct RES_RECORD_INV
{
	unsigned short name;
	unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
    uint32_t address;
};

struct DNS_PACKAGE {
	
	struct DNS_HEADER* dns_header;
	struct QUERY ** dns_queries;
	struct RES_RECORD** dns_answers;
	struct RES_RECORD** dns_authorities;
	struct RES_RECORD** dns_aditionals;
};

struct DNS_PACKAGE1 {	// Aqu'i se incluye la informaci'on ip pertinente a nuestros objetivos.

	unsigned char* package;	//
	unsigned int size;	//
	struct nfq_iphdr* ip_header;	//
	struct nfq_udphdr* udp_header;	//
	unsigned char* dns_message;	//
	unsigned int dns_message_size;	//
	struct DNS_HEADER* dns_header;	//
	struct QUERY ** dns_queries;
	struct RES_RECORD** dns_answers;
	struct RES_RECORD** dns_authorities;
	struct RES_RECORD** dns_aditionals;
};

/*struct IP_PACKAGE {	// Aqu'i se incluye la informaci'on ip pertinente a nuestros objetivos.

	unsigned char* package;	//
	unsigned int size;	//
	struct nfq_iphdr* ip_header;	//
	struct nfq_udphdr* udp_header;	//
	unsigned char* dns_message;	//
	unsigned int dns_message_size;	//
	struct DNS_PACKAGE* DNS_package;
};*/

union ald {	// Esto significa aplication layer data

	struct DNS_PACKAGE* DNS_data;
};

union tlh {	// Esto significa transport layer header
	
	struct nfq_tcphdr* tcp_header;
	struct nfq_udphdr* udp_header;
};

struct IP_PACKAGE {	// Aqu'i se incluye la informaci'on ip pertinente a nuestros objetivos.

	struct nfq_iphdr* ip_header;
	union tlh* _;
	union ald* __;
};

typedef struct otro_str {
	
    http_request* h;
    GString* dest;
    peer* p;
    unsigned int counter;
    unsigned int solved_sites;

} otro_struct;

union dns_rq_data_t {
	
	comm_interface* wsk_comm_interface;
	struct otro_str* otro;
	
};//dns_rq_data;

/*struct dns_rq_t {
	
	unsigned int type;			// Define desde donde se hizo la solicitud DNS.
	union dns_rq_data_t datos;	// Aqu'i van los datos espec'ificos que se van a modificar.
	
};//dns_rq;*/

struct datos_usuario {
	
	void (*return_function)(struct respuesta*,void* user_data);
	void* user_d;
};

struct dns_rq_t {
	
	struct datos_usuario du;
	unsigned char DNS_package[4096];
	size_t size;
	time_t sended_time;
	unsigned short unique_id;
	unsigned char* name;
};

struct requests_queue_t {
	
	gboolean locked;
	struct dns_rq_t** items;
	unsigned int cantidad;
};

struct delayed {
	
	struct dns_rq_t* itm;
	unsigned int contador;
};

struct respuesta {
	
	unsigned char* pregunta;
	struct sockaddr_in** ip_addresses;
	unsigned char** nombres;
};

// functions

void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host);
unsigned char* ReadName(unsigned char* reader,unsigned char* buffer,int* count);
char* read_label(char** begining, unsigned int *total_bytes);
struct QUERY* read_query(char** begining, unsigned int* total_bytes);
struct IP_PACKAGE* parse_IP_PACKAGE(unsigned char* payload);
struct DNS_PACKAGE* parse_DNS_PACKAGE(unsigned char* payload);
struct DNS_PACKAGE1* parse_DNS_message(char* payload, int payload_size);
void free_DNS_message(struct DNS_PACKAGE1* DNSpackage);
void free_IP_PACKAGE(struct IP_PACKAGE* IPpackage);
void free_DNS_PACKAGE(struct DNS_PACKAGE* DNSpackage);
void dns_callback(GObject *source_object,GAsyncResult *res,gpointer user_data);
gboolean add_request_delayed(struct dns_rq_t* a);

// Clases

class DNS_resolver {
	
	// Private fields
	
	unsigned short contador_id;
	struct requests_queue_t* requests_queue;
	
	// Private functions
	
	public:
	
	// Public fields
	
	GIOChannel *sock_DNS;
	
	// Public functions
	
	DNS_resolver();
	~DNS_resolver();
	
	gboolean is_queue_locked();
	void lock_queue(gboolean status);
	
	void solve_address(unsigned char* name,int type_q, void (*return_func)(struct respuesta*,void* user_data),void* user_data);
	//void solve_name(uint32_t address, void (*return_func)(struct respuesta*,void* user_data),void* user_data);
	void solve_name(unsigned char* name, void (*return_func)(struct respuesta*,void* user_data),void* user_data);
	
	void add_to_queue(struct dns_rq_t* rq);
	void remove_from_queue(struct dns_rq_t* rq);
	void run_queue();
	
	void DNS_receive(unsigned char *buf1, guint size);
	void return_request(struct DNS_PACKAGE* answer);
	void free_respuesta (struct respuesta* resp);
};
