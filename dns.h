#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>	//printf
#include <string.h>	//strlen
#include <stdlib.h>	//malloc
#include <sys/socket.h>	//you know what this is for
#include <arpa/inet.h>	//inet_addr , inet_ntoa , ntohs etc
#include <netinet/in.h>
#include <unistd.h>	//getpid

//Types of DNS resource records :)
#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server

struct nfq_iphdr
{
/*
#if defined(__LITTLE_ENDIAN_BITFIELD)
uint8_t ihl:4,
version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
*/
uint8_t version:4,
ihl:4;
/*
#endif
*/
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
/*
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
*/
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
/*
#endif
*/
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

//Query Structure
struct QUERY
{
    unsigned char *name;
    char size;
    unsigned short qtype;
    unsigned short qclass;
};

struct DNS_PACKAGE {	// Aqu'i se incluye la informaci'on ip pertinente a nuestros objetivos.

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


// functions

unsigned char* ReadName(unsigned char* reader,unsigned char* buffer,int* count);
char* read_label(char** begining, unsigned int *total_bytes);
struct QUERY* read_query(char** begining, unsigned int* total_bytes);
struct DNS_PACKAGE* parse_DNS_message (char* payload, int payload_size);
void free_DNS_message(struct DNS_PACKAGE*);
