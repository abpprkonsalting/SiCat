# include "dns.h"

extern class DNS_resolver* resolver;

gboolean add_request_delayed(struct dns_rq_t* a) {
	
	if (resolver->is_queue_locked() == TRUE) return TRUE;
	else {
		
		resolver->lock_queue(TRUE);
		resolver->add_to_queue(a);
		resolver->lock_queue(FALSE);
		g_debug("agregada a la cola la solicitud dns para el sitio %s de manera demorada",a);
	
	}
	return FALSE;
}

gboolean return_request_delayed(struct DNS_PACKAGE *full_dns_answer ) {
	
	if (resolver->is_queue_locked() == TRUE) return TRUE;
	else {
		
		resolver->lock_queue(TRUE);
		resolver->return_request(full_dns_answer);
		resolver->lock_queue(FALSE);
	}
	return FALSE;
}

/*
 * This will convert www.google.com to 3www6google3com 
 * got it :)
 * */
 
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host) 
{
	int lock = 0 , i;
	strcat((char*)host,".");
	
	for(i = 0 ; i < (int)strlen((char*)host) ; i++) 
	{
		if(host[i]=='.') 
		{
			*dns++ = i-lock;
			for(;lock<i;lock++) 
			{
				*dns++=host[lock];
			}
			lock++; //or lock=i+1;
		}
	}
	*dns++='\0';
}

unsigned char* ReadName(unsigned char* reader,unsigned char* buffer,int* count) {
	
	unsigned char *name, *temp;
	unsigned int p=0,jumped=0,offset;
	int i , j;

	*count = 1;
	name = (unsigned char*)g_new0(char,256);//  calloc(char,256);

	name[0]='\0';

	//g_debug((char*)reader);
	//read the names in 3www6google3com format
	while(*reader!=0)
	{
		if(*reader>=192)
		{
			offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
			reader = buffer + offset - 1;
			jumped = 1; //we have jumped to another location so counting wont go up!
		}
		else
		{
			name[p++]=*reader;
		}

		reader = reader+1;

		if(jumped==0)
		{
			*count = *count + 1; //if we havent jumped to another location then we can count up
		}
	}

	name[p]='\0'; //string complete
	if(jumped==1)
	{
		*count = *count + 1; //number of steps we actually moved forward in the packet
	}

	//now convert 3www6google3com0 to www.google.com
	for(i=0;i<(int)strlen((const char*)name);i++) 
	{
		p=name[i];
		for(j=0;j<(int)p;j++) 
		{
			name[i]=name[i+1];
			i=i+1;
		}
		name[i]='.';
	}
	//name[i-1]='\0'; //remove the last dot
	temp = (unsigned char*)g_strrstr((char*)name,".");
	*temp = '\0';
	//g_debug((char*)name);
	return name;
}

char* read_label(unsigned char** begining, unsigned int *total_bytes){
	
	char* result = NULL;
	char cantidad = (char)**begining;
	**begining = '.';
	//g_debug("cantidad = %d", cantidad);
	//g_debug("begining antes= %d",*begining);
	//g_debug("total_bytes antes= %d",*total_bytes);
	
	if ((unsigned int)cantidad <= *total_bytes){
		
		result = g_new0(char,cantidad + 2);
		memcpy(result,*begining,cantidad + 1);
		//g_debug(result);
		
		for (char i = 0; i < cantidad; i++) (*begining)++;
		(*begining)++;

		*total_bytes = *total_bytes - (unsigned int)cantidad - 1;
		
		//g_debug("begining despues= %d",*begining);
		//g_debug("total_bytes despues= %d",*total_bytes);
		
		return result;
	}
	else return result;
	return result;
}

struct QUERY* read_query(unsigned char** begining, unsigned int* total_bytes){
	
	char *label_temp, *result_temp, *result = NULL;
	
	 struct QUERY* query_temp = g_new0(struct QUERY,1);
	 
	// Leyendo el qname
	while (**begining != 0){
		
		label_temp = read_label(begining,total_bytes);
		if (label_temp != NULL){
			
			result_temp = result;
			if (result == NULL) result = g_new0(char,strlen(label_temp)+1);
			else result = g_new0(char,strlen(result)+strlen(label_temp)+1);
			if (result_temp != NULL) strcpy(result,result_temp);
			g_free(result_temp);
			strcat(result,label_temp);
		}
		else {
			
			g_free(query_temp);
			return NULL;
		}
	}
	query_temp->name = (unsigned char*)strdup(result+1);
	g_free(result);
	//query_temp->qtype = (unsigned short)ntohs(*(begining + 1));
	//query_temp->qclass = (unsigned short)ntohs(*(begining + 3));
	return query_temp;
	 
}

struct IP_PACKAGE* parse_IP_PACKAGE(unsigned char* payload){
	
	// A esta funci'on se le debe entrar con un paquete IP completo, es decir que el payload tenga todo el mensaje,
	// de cualquier manera se chequear'a en el encabezado IP que el formato del paquete sea correcto.
	
	gchar ip[16];
	unsigned char* aplic_layer_data;
	
	// Chequear que esto no es un mensaje fragmentado.
	
	struct IP_PACKAGE* IPpackage = g_new0(struct IP_PACKAGE,1);
	IPpackage->ip_header = (struct nfq_iphdr*) payload;
	
	inet_ntop (AF_INET, &IPpackage->ip_header->saddr, ip, 16);
	g_debug("parse_IP_PACKAGE: DNS package ip source address = %s",ip);
	
	IPpackage->_->udp_header = (struct nfq_udphdr*) (payload + sizeof(struct nfq_iphdr));
	aplic_layer_data = payload + sizeof(struct nfq_iphdr) + sizeof(struct nfq_udphdr);
	
	IPpackage->__->DNS_data = parse_DNS_PACKAGE(aplic_layer_data);
	
	return IPpackage;
	
}

struct DNS_PACKAGE* parse_DNS_PACKAGE(unsigned char* payload){
	
	struct DNS_PACKAGE* DNSpackage;
	unsigned char* begining;
	int stop;
	
	DNSpackage = g_new0(struct DNS_PACKAGE,1);

	struct DNS_HEADER* tmp = (struct DNS_HEADER*) payload;
	
	DNSpackage->dns_header = g_new0(struct DNS_HEADER,1);
	
	DNSpackage->dns_header->id = tmp->id;
	//DNSpackage->dns_header->id = ntohs(tmp->id);
	DNSpackage->dns_header->rd = tmp->rd;
	
	DNSpackage->dns_header->tc = tmp->tc;
	DNSpackage->dns_header->aa = tmp->aa;
	DNSpackage->dns_header->opcode = tmp->opcode;
	DNSpackage->dns_header->qr = tmp->qr;
	DNSpackage->dns_header->rcode = tmp->rcode;
	DNSpackage->dns_header->cd = tmp->cd;
	DNSpackage->dns_header->ad = tmp->ad;
	DNSpackage->dns_header->z = tmp->z;
	DNSpackage->dns_header->ra = tmp->ra;
	DNSpackage->dns_header->q_count = ntohs(tmp->q_count);
	DNSpackage->dns_header->ans_count = ntohs(tmp->ans_count);
	DNSpackage->dns_header->auth_count = ntohs(tmp->auth_count);
	DNSpackage->dns_header->add_count = ntohs(tmp->add_count);

	DNSpackage->dns_queries = g_new0(struct QUERY*,DNSpackage->dns_header->q_count);
	DNSpackage->dns_answers = g_new0(struct RES_RECORD*,DNSpackage->dns_header->ans_count);
	DNSpackage->dns_authorities = g_new0(struct RES_RECORD*,DNSpackage->dns_header->auth_count);
	DNSpackage->dns_aditionals = g_new0(struct RES_RECORD*,DNSpackage->dns_header->add_count);
	
	begining = payload + sizeof(struct DNS_HEADER);
	stop=0;
	
	//Start reading queries
	
	g_debug("parse_DNS_message: queries = %u",DNSpackage->dns_header->q_count);
	
	for(int i=0;i<DNSpackage->dns_header->q_count;i++){
		
		DNSpackage->dns_queries[i] = g_new0(struct QUERY,1);
		DNSpackage->dns_queries[i]->name = ReadName(begining,payload,&stop);
		g_debug("parse_DNS_message: query name # %d = %s",i+1,(char*)DNSpackage->dns_queries[i]->name);
		begining = begining + stop;
		DNSpackage->dns_queries[i]->qtype = ntohs(*begining);
		DNSpackage->dns_queries[i]->qclass = ntohs(*begining + 2);
		begining++;
		begining++;
		begining++;
		begining++;
	}
	
	//Start reading answers
	
	g_debug("parse_DNS_message: answers = %d",DNSpackage->dns_header->ans_count);
	
	for(int i=0;i<DNSpackage->dns_header->ans_count;i++){
		
		DNSpackage->dns_answers[i] = g_new0(struct RES_RECORD,1);
		DNSpackage->dns_answers[i]->name = ReadName(begining,payload,&stop);
		g_debug("parse_DNS_message: answer # %d name = %s",i+1,(char*)DNSpackage->dns_answers[i]->name);
		begining = begining + stop;

		DNSpackage->dns_answers[i]->resource = (struct R_DATA*)(begining);
		begining = begining + sizeof(struct R_DATA);

		if(ntohs(DNSpackage->dns_answers[i]->resource->type) == 1) //if its an ipv4 address
		{
			DNSpackage->dns_answers[i]->rdata = (unsigned char*)malloc(ntohs(DNSpackage->dns_answers[i]->resource->data_len));

			for(int j=0 ; j<ntohs(DNSpackage->dns_answers[i]->resource->data_len) ; j++)
			{
				DNSpackage->dns_answers[i]->rdata[j]=begining[j];
			}

			DNSpackage->dns_answers[i]->rdata[ntohs(DNSpackage->dns_answers[i]->resource->data_len)] = '\0';

			begining = begining + ntohs(DNSpackage->dns_answers[i]->resource->data_len);
			
			long *p1;
			struct sockaddr_in a;
			p1=(long*)DNSpackage->dns_answers[i]->rdata;
			a.sin_addr.s_addr=(*p1);
			
			g_debug("parse_DNS_message: answer # %d data = %s",i+1,(char*)inet_ntoa(a.sin_addr));
		}
		else
		{
			DNSpackage->dns_answers[i]->rdata = ReadName(begining,payload,&stop);
			begining = begining + stop;
			g_debug("parse_DNS_message: answer # %d data = %s",i+1,DNSpackage->dns_answers[i]->rdata);
		}
	}
	
	/*
	//read authorities
	g_debug("parse_DNS_message: authorities = %d",DNSpackage->dns_header->auth_count);
	for(int i=0;i<DNSpackage->dns_header->auth_count;i++)
	{
		DNSpackage->dns_authorities[i] = g_new0(struct RES_RECORD,1);
		DNSpackage->dns_authorities[i]->name=ReadName(begining,payload,&stop);
		g_debug("parse_DNS_message: authorities name # %d = %s",i+1,(char*)DNSpackage->dns_authorities[i]->name);
		begining+=stop;

		DNSpackage->dns_authorities[i]->resource=(struct R_DATA*)(begining);
		begining+=sizeof(struct R_DATA);

		DNSpackage->dns_authorities[i]->rdata=ReadName(begining,DNSpackage->dns_message,&stop);
		begining+=stop;
	}
	
	//read additional
	g_debug("parse_DNS_message: additionals = %d",DNSpackage->dns_header->add_count);
	for(int i=0;i<DNSpackage->dns_header->add_count;i++)
	{
		DNSpackage->dns_aditionals[i] = g_new0(struct RES_RECORD,1);
		DNSpackage->dns_aditionals[i]->name=ReadName(begining,payload,&stop);
		g_debug("parse_DNS_message: aditionals name # %d = %s",i+1,(char*)DNSpackage->dns_aditionals[i]->name);
		begining+=stop;

		DNSpackage->dns_aditionals[i]->resource=(struct R_DATA*)(begining);
		begining+=sizeof(struct R_DATA);

		if(ntohs(DNSpackage->dns_aditionals[i]->resource->type)==1)
		{
			DNSpackage->dns_aditionals[i]->rdata = (unsigned char*)malloc(ntohs(DNSpackage->dns_aditionals[i]->resource->data_len));
			for(int j=0;j<ntohs(DNSpackage->dns_aditionals[i]->resource->data_len);j++)
			DNSpackage->dns_aditionals[i]->rdata[j]=begining[j];

			DNSpackage->dns_aditionals[i]->rdata[ntohs(DNSpackage->dns_aditionals[i]->resource->data_len)]='\0';
			begining+=ntohs(DNSpackage->dns_aditionals[i]->resource->data_len);
		}
		else
		{
			DNSpackage->dns_aditionals[i]->rdata=ReadName(begining,payload,&stop);
			begining+=stop;
		}
	}
	*/
	
	return DNSpackage;

}

void free_IP_PACKAGE(struct IP_PACKAGE* IPpackage){
	return;
}

struct DNS_PACKAGE1* parse_DNS_message(char* payload, int payload_size){
	
	struct DNS_PACKAGE1* DNSpackage;
	//gchar ip[16];
	unsigned char* begining;
	//unsigned int total;
	//struct RES_RECORD answers[20],auth[20],addit[20]; //the replies from the DNS server
	int stop;
	
	// Parsing del datagrama IP completo a la estructura DNSpackage, la cual incluye todo el paquete IP.
	
	DNSpackage = g_new0(struct DNS_PACKAGE1,1);
	
	DNSpackage->size = payload_size;
	
	DNSpackage->package = (unsigned char*) g_new0(gchar,DNSpackage->size + 2);
	memcpy(DNSpackage->package,payload,DNSpackage->size);
	
	DNSpackage->ip_header = (struct nfq_iphdr*) DNSpackage->package;

	/*inet_ntop (AF_INET, &DNSpackage->ip_header->saddr, ip, 16);
	g_debug("DNS package ip source address = %s",ip);*/
	
	DNSpackage->udp_header = (struct nfq_udphdr*) DNSpackage->package + sizeof(struct nfq_iphdr);
		
	// Aqu'i empiezo a parsear el protocolo de aplicaci'on (DNS).
		
	DNSpackage->dns_message = DNSpackage->package + sizeof(struct nfq_iphdr) + sizeof(struct nfq_udphdr);
	DNSpackage->dns_message_size = (DNSpackage->size - sizeof(struct nfq_iphdr) - sizeof(struct nfq_udphdr));
	DNSpackage->dns_header = (struct DNS_HEADER*) DNSpackage->dns_message;
	
	DNSpackage->dns_queries = g_new0(struct QUERY*,ntohs(DNSpackage->dns_header->q_count));
	DNSpackage->dns_answers = g_new0(struct RES_RECORD*,ntohs(DNSpackage->dns_header->ans_count));
	DNSpackage->dns_authorities = g_new0(struct RES_RECORD*,ntohs(DNSpackage->dns_header->auth_count));
	DNSpackage->dns_aditionals = g_new0(struct RES_RECORD*,ntohs(DNSpackage->dns_header->add_count));
	
	begining = DNSpackage->dns_message + sizeof(struct DNS_HEADER);
	//total = DNSpackage->dns_message_size - sizeof(struct DNS_HEADER);
	
	/*for(int i=0; i < ntohs(DNSpackage->dns_header->q_count); i++) {
		
		DNSpackage->dns_queries[i] = read_query(&begining,&total);
		g_debug("requested name number %d = %s",i+1, DNSpackage->dns_queries[i]->name);
	}*/
	
	//Start reading queries
	
	//g_debug("queries = %d",ntohs(DNSpackage->dns_header->q_count));
	stop=0;
	
	g_debug("parse_DNS_message: queries = %d",ntohs(DNSpackage->dns_header->q_count));
	for(int i=0;i<ntohs(DNSpackage->dns_header->q_count);i++){
		
		DNSpackage->dns_queries[i] = g_new0(struct QUERY,1);
		DNSpackage->dns_queries[i]->name = ReadName(begining,DNSpackage->dns_message,&stop);
		g_debug("parse_DNS_message: query name # %d = %s",i+1,(char*)DNSpackage->dns_queries[i]->name);
		begining = begining + stop;
		DNSpackage->dns_queries[i]->qtype = ntohs(*begining);
		DNSpackage->dns_queries[i]->qclass = ntohs(*begining + 2);
		begining++;
		begining++;
		begining++;
		begining++;
	}
	
	g_debug("parse_DNS_message: answers = %d",ntohs(DNSpackage->dns_header->ans_count));
	//Start reading answers
	for(int i=0;i<ntohs(DNSpackage->dns_header->ans_count);i++){
		
		DNSpackage->dns_answers[i] = g_new0(struct RES_RECORD,1);
		DNSpackage->dns_answers[i]->name = ReadName(begining,DNSpackage->dns_message,&stop);
		g_debug("parse_DNS_message: answer # %d name = %s",i+1,(char*)DNSpackage->dns_answers[i]->name);
		begining = begining + stop;

		DNSpackage->dns_answers[i]->resource = (struct R_DATA*)(begining);
		begining = begining + sizeof(struct R_DATA);

		if(ntohs(DNSpackage->dns_answers[i]->resource->type) == 1) //if its an ipv4 address
		{
			DNSpackage->dns_answers[i]->rdata = (unsigned char*)malloc(ntohs(DNSpackage->dns_answers[i]->resource->data_len));

			for(int j=0 ; j<ntohs(DNSpackage->dns_answers[i]->resource->data_len) ; j++)
			{
				DNSpackage->dns_answers[i]->rdata[j]=begining[j];
			}

			DNSpackage->dns_answers[i]->rdata[ntohs(DNSpackage->dns_answers[i]->resource->data_len)] = '\0';

			begining = begining + ntohs(DNSpackage->dns_answers[i]->resource->data_len);
			
			long *p1;
			struct sockaddr_in a;
			p1=(long*)DNSpackage->dns_answers[i]->rdata;
			a.sin_addr.s_addr=(*p1);
			
			g_debug("parse_DNS_message: answer # %d data = %s",i+1,(char*)inet_ntoa(a.sin_addr));
		}
		else
		{
			DNSpackage->dns_answers[i]->rdata = ReadName(begining,DNSpackage->dns_message,&stop);
			begining = begining + stop;
			g_debug("parse_DNS_message: answer # %d data = %s",i+1,DNSpackage->dns_answers[i]->rdata);
		}
	}
	
	/*
	//read authorities
	g_debug("parse_DNS_message: authorities = %d",ntohs(DNSpackage->dns_header->auth_count));
	for(int i=0;i<ntohs(DNSpackage->dns_header->auth_count);i++)
	{
		DNSpackage->dns_authorities[i] = g_new0(struct RES_RECORD,1);
		DNSpackage->dns_authorities[i]->name=ReadName(begining,DNSpackage->dns_message,&stop);
		g_debug("parse_DNS_message: authorities name # %d = %s",i+1,(char*)DNSpackage->dns_authorities[i]->name);
		begining+=stop;

		DNSpackage->dns_authorities[i]->resource=(struct R_DATA*)(begining);
		begining+=sizeof(struct R_DATA);

		DNSpackage->dns_authorities[i]->rdata=ReadName(begining,DNSpackage->dns_message,&stop);
		begining+=stop;
	}
	
	//read additional
	g_debug("parse_DNS_message: additionals = %d",ntohs(DNSpackage->dns_header->add_count));
	for(int i=0;i<ntohs(DNSpackage->dns_header->add_count);i++)
	{
		DNSpackage->dns_aditionals[i] = g_new0(struct RES_RECORD,1);
		DNSpackage->dns_aditionals[i]->name=ReadName(begining,DNSpackage->dns_message,&stop);
		g_debug("parse_DNS_message: aditionals name # %d = %s",i+1,(char*)DNSpackage->dns_aditionals[i]->name);
		begining+=stop;

		DNSpackage->dns_aditionals[i]->resource=(struct R_DATA*)(begining);
		begining+=sizeof(struct R_DATA);

		if(ntohs(DNSpackage->dns_aditionals[i]->resource->type)==1)
		{
			DNSpackage->dns_aditionals[i]->rdata = (unsigned char*)malloc(ntohs(DNSpackage->dns_aditionals[i]->resource->data_len));
			for(int j=0;j<ntohs(DNSpackage->dns_aditionals[i]->resource->data_len);j++)
			DNSpackage->dns_aditionals[i]->rdata[j]=begining[j];

			DNSpackage->dns_aditionals[i]->rdata[ntohs(DNSpackage->dns_aditionals[i]->resource->data_len)]='\0';
			begining+=ntohs(DNSpackage->dns_aditionals[i]->resource->data_len);
		}
		else
		{
			DNSpackage->dns_aditionals[i]->rdata=ReadName(begining,DNSpackage->dns_message,&stop);
			begining+=stop;
		}
	}
	* */
	
	return DNSpackage;

}

void free_DNS_message(struct DNS_PACKAGE1* DNSpackage){
	

	for(int i=0;i<ntohs(DNSpackage->dns_header->ans_count);i++){
		
		g_free(DNSpackage->dns_answers[i]->name);
		g_free(DNSpackage->dns_answers[i]->rdata);
		g_free(DNSpackage->dns_answers[i]);
	}
	for(int i=0;i<ntohs(DNSpackage->dns_header->q_count);i++){
		
		g_free(DNSpackage->dns_queries[i]->name);
		g_free(DNSpackage->dns_queries[i]);
	}
	g_free(DNSpackage->dns_queries);
	g_free(DNSpackage->dns_answers);
	g_free(DNSpackage->dns_authorities);
	g_free(DNSpackage->dns_aditionals);
	g_free(DNSpackage->package);
	g_free(DNSpackage);
	
}

/*void dns_callback(GObject *source_object,GAsyncResult *res,gpointer user_data){
	
	dns_rq_t *da = (dns_rq_t*)user_data;
	
	GList *mylist;
	gchar* address;
	GError* gerror = NULL;
	
	mylist = g_resolver_lookup_by_name_finish((GResolver *)source_object,res,&gerror);
	
	if (gerror != NULL) {
				
		g_warning("dns_callback: g_resolver_lookup_by_name_finish error: %s",gerror->message);
		
		//if (da->type == 0) da->datos.wsk_comm_interface->wsk_set_status(WSK_DISCONNECTED,"dns_callback");
		
		return;
	}
	
	if (mylist != NULL){
		
		if (da->type == 0){
			
			address = g_inet_address_to_string((GInetAddress *)mylist->data);
			
			//wsk_comm_interface->set_wsk_server_IP(address);
			//da->datos.wsk_comm_interface->set_wsk_server_IP(address);
			
			g_resolver_free_addresses(mylist);
			//int x = wsk_comm_interface->wsk_create();
			//int x = da->datos.wsk_comm_interface->wsk_create();
			//if (x == -1){
					
			//	g_warning("dns_callback: websocket initialization error, retrying...");
				//da->datos.wsk_comm_interface->wsk_set_status(WSK_DISCONNECTED,"dns_callback");
			//}
		}
	}
	else {
		
		if (da->type == 0){
			
			g_warning("dns_callback: g_resolver_lookup_by_name_finish error ..");
			//da->datos.wsk_comm_interface->wsk_set_status(WSK_DISCONNECTED,"dns_callback");
		}
	}
}*/

/***************************** class DNS_resolver methods ********************/
#ifdef MFRAME

	// Constructor
	DNS_resolver::DNS_resolver(){
		
		struct sockaddr_in local_addr, remote_addr;
		gchar* val;
	    int fd, r, n = 1;
	    GError* gerror = NULL;
	    
		g_debug("DNS_resolver::constructor: initializing the DNS_resolver");
	
	    local_addr.sin_family = AF_INET;
	    remote_addr.sin_family = AF_INET;
	    remote_addr.sin_port = htons(53);
	
	    fd = socket( PF_INET, SOCK_DGRAM, 0 );
	    
	    if (fd < 0) {

	    	g_message("DNS_resolver::constructor: socket failed: %m");
	    	g_assert(0);
	    }
	    
	    r = inet_aton("127.0.0.1", &local_addr.sin_addr );
	    
	    if (r == 0){

	    	g_message("DNS_resolver::constructor: inet_aton failed on 127.0.0.1: %m");
	    	g_assert(0);
	    }
	   
	    r = bind( fd, (struct sockaddr *)&local_addr, sizeof(local_addr) );
	    
	    if (r == -1) {

	    	g_message("DNS_resolver::constructor: bind failed on 127.0.0.1: %m");
	    	g_assert(0);
	    }
	    
	    n = fcntl( fd, F_GETFL, 0 );
	    if (n == -1) {

			g_message("DNS_resolver::constructor: fcntl F_GETFL on 127.0.0.1: %m");
	    	g_assert(0);
	    }
	    
	    r = fcntl( fd, F_SETFL, n | O_NONBLOCK);
	
		if (r == -1) {
			
			g_message("DNS_resolver::constructor:fcntl F_SETFL O_NONBLOCK on 127.0.0.1: %m");
	    	g_assert(0);
		}
		/*
		//val = (gchar*) g_hash_table_lookup(nocat_conf, "DNSAddr" );
	    val = NULL;
	    if (val == NULL) val = strdup("127.0.0.1");
	    
	    r = inet_aton( val, &remote_addr.sin_addr );
	    
	    if (r == 0){

	    	g_message("DNS_resolver::constructor: inet_aton failed on %s: %m", val);
	    	g_assert(0);
	    }
	    
	    r = connect(fd,(struct sockaddr *)&remote_addr, sizeof(remote_addr));
	    
	    if (r < 0){

	    	g_message("DNS_resolver::constructor: connect failed on %s: %m", val);
	    	g_assert(0);
	    }*/
	    sock_DNS = g_io_channel_unix_new(fd);
	    g_io_channel_set_encoding(sock_DNS,NULL,&gerror);
	    // Inicializar la cola de requests
	    
	    requests_queue = g_new0(struct requests_queue_t, 1);
	    
		requests_queue->locked = FALSE;
		requests_queue->items = g_new0(struct dns_rq_t*, 1);
		requests_queue->cantidad = 1;
	    
	    contador_id = 0;

	}
	
	void DNS_resolver::solve_address(unsigned char* name,int type_q , void (*return_func)(struct respuesta*,void* user_data),void* user_data){
		
		// Esta funci'on lo que tiene que hacer es crear una estructura dns_rq_t e insertarla en el arreglo de 
		// requests pendientes.
		
		//g_debug("DNS_resolver::solve_address: entering");
		
		struct DNS_HEADER *dns = NULL;
		unsigned char *qname;
		struct QUESTION *qinfo = NULL;
		
		struct dns_rq_t* rq = g_new0(struct dns_rq_t,1);
		
		bzero (rq->DNS_package, 4096);
		rq->du.return_function = (*return_func);
		rq->du.user_d = user_data;
		rq->sended_time = 0;
		contador_id++;
		rq->unique_id = htons(contador_id);
		rq->name = (unsigned char*)strdup((const char*)name);

		// Llenar el header de la solicitud DNS
		
		//Set the DNS structure to standard queries
		dns = (struct DNS_HEADER *)&(rq->DNS_package);
		
		dns->id = rq->unique_id;
		dns->qr = 0;
		dns->opcode = 0;
		dns->aa = 0;
		dns->tc = 0;
		dns->rd = 1;
		dns->ra = 0;
		dns->z = 0;
		dns->ad = 0;
		dns->cd = 0;
		dns->rcode = 0;
		dns->q_count = htons(1);
		dns->ans_count = 0;
		dns->auth_count = 0;
		dns->add_count = 0;
		
		//point to the query portion
		qname =(unsigned char*)&rq->DNS_package[sizeof(struct DNS_HEADER)];
		
		unsigned char* tm_name = (unsigned char*)strdup((const char*)name);
		ChangetoDnsNameFormat(qname,tm_name);
		g_free(tm_name);

		qinfo =(struct QUESTION*)&rq->DNS_package[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)];
		
		qinfo->qtype = htons(type_q); //type of the query , A , MX , CNAME , NS etc
		qinfo->qclass = htons(1); //its internet (lol)
		
		rq->size = sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION);

		// Ya est'a creada la estructura dns_rq_t ahora toca insertarla en el arreglo.

		if (requests_queue->locked == TRUE) g_timeout_add(50, (GSourceFunc) add_request_delayed,rq);
		else {

			requests_queue->locked = TRUE;
			add_to_queue(rq);
			requests_queue->locked = FALSE;
			//g_debug("agregada a la cola la solicitud dns para el sitio %s",name);
		}
		return;
	}

	void DNS_resolver::solve_name(unsigned char* name, void (*return_func)(struct respuesta*,void* user_data),void* user_data){
		
		// Esta funci'on lo que tiene que hacer es crear una estructura dns_rq_t e insertarla en el arreglo de 
		// requests pendientes.
		
		//g_debug("DNS_resolver::solve_address: entering");
		
		struct DNS_HEADER *dns = NULL;
		unsigned char *qname;
		struct QUESTION *qinfo = NULL;
		
		struct dns_rq_t* rq = g_new0(struct dns_rq_t,1);
		
		bzero (rq->DNS_package, 4096);
		rq->du.return_function = (*return_func);
		rq->du.user_d = user_data;
		rq->sended_time = 0;
		contador_id++;
		rq->unique_id = htons(contador_id);
		rq->name = (unsigned char*)strdup((const char*)name);

		// Llenar el header de la solicitud DNS
		
		//Set the DNS structure to standard queries
		dns = (struct DNS_HEADER *)&(rq->DNS_package);
		
		dns->id = rq->unique_id;
		dns->qr = 0;
		dns->opcode = 0;
		dns->aa = 0;
		dns->tc = 0;
		dns->rd = 1;
		dns->ra = 0;
		dns->z = 0;
		dns->ad = 0;
		dns->cd = 0;
		dns->rcode = 0;
		dns->q_count = htons(1);
		dns->ans_count = 0;
		dns->auth_count = 0;
		dns->add_count = 0;
		
		//point to the query portion
		qname =(unsigned char*)&rq->DNS_package[sizeof(struct DNS_HEADER)];
		
		unsigned char* tm_name = (unsigned char*)strdup((const char*)name);
		ChangetoDnsNameFormat(qname,tm_name);
		g_free(tm_name);

		qinfo =(struct QUESTION*)&rq->DNS_package[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)];
		
		qinfo->qtype = htons(T_PTR); //type of the query , A , MX , CNAME , NS etc
		qinfo->qclass = htons(1); //its internet (lol)
		
		rq->size = sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION);

		// Ya est'a creada la estructura dns_rq_t ahora toca insertarla en el arreglo.

		if (requests_queue->locked == TRUE) g_timeout_add(50, (GSourceFunc) add_request_delayed, rq);
		else {

			requests_queue->locked = TRUE;
			add_to_queue(rq);
			requests_queue->locked = FALSE;
			//g_debug("agregada a la cola la solicitud dns para el sitio %s",name);
		}
		return;
	}
	
/*	void DNS_resolver::solve_name(uint32_t address, void (*return_func)(struct respuesta*,void* user_data),void* user_data){
		
		g_debug("DNS_resolver::solve_name: entering");
		
		struct DNS_HEADER *dns = NULL;
		struct RES_RECORD_INV *RR;
		struct QUESTION *qinfo = NULL;
		
		struct dns_rq_t* rq = g_new0(struct dns_rq_t,1);
		
		bzero (rq->DNS_package, 4096);
		rq->du.return_function = (*return_func);
		rq->du.user_d = user_data;
		rq->sended_time = 0;
		contador_id++;
		rq->unique_id = htons(contador_id);
		rq->name = (unsigned char*)strdup("ip address");
		
		// Llenar el header de la solicitud DNS
		
		//Set the DNS structure to standard queries
		dns = (struct DNS_HEADER *)&(rq->DNS_package);
		
		dns->id = rq->unique_id;
		dns->qr = 0;
		dns->opcode = 1;
		dns->aa = 0;
		dns->tc = 0;
		dns->rd = 1;
		dns->ra = 0;
		dns->z = 0;
		dns->ad = 0;
		dns->cd = 0;
		dns->rcode = 0;
		dns->q_count = 0;
		dns->ans_count = htons(1);
		dns->auth_count = 0;
		dns->add_count = 0;
		
		//point to the answer portion
		RR = (struct RES_RECORD_INV*)&rq->DNS_package[sizeof(struct DNS_HEADER)];
		RR->name = 0;
		RR->type = htons(T_A);
		RR->_class = htons(1);
		RR->ttl = 0;
		RR->data_len = htons(4);
		RR->address = address;
		
		if (requests_queue->locked == TRUE) {

			struct delayed *a = g_new0(struct delayed,1);
			a->itm = rq;
			a->contador = 0;
			g_timeout_add(100, (GSourceFunc) add_request_delayed, a);
		}
		else {

			requests_queue->locked = TRUE;
			add_to_queue(rq);
			requests_queue->locked = FALSE;
			//g_debug("agregada a la cola la solicitud dns para el sitio %s",name);
		}
		return;
		
	}*/
		
	void DNS_resolver::add_to_queue(struct dns_rq_t* rq){
		
		//g_debug("DNS_resolver::add_to_queue: entering");
		struct dns_rq_t** tmp = g_new0(struct dns_rq_t*,requests_queue->cantidad + 1);
		
		for (unsigned int i = 0; i < requests_queue->cantidad;i++) tmp[i] = requests_queue->items[i];
		
		g_free(requests_queue->items);
		requests_queue->items = tmp;
		requests_queue->items[requests_queue->cantidad-1] = rq;
		requests_queue->cantidad++;
	}
	
	void DNS_resolver::run_queue(){
		
		//guint cond;
		int r;
		struct sockaddr_in remote_addr;
		g_debug("DNS_resolver::runnning queue");
		
		remote_addr.sin_family = AF_INET;
		r = inet_aton( "127.0.0.1", &remote_addr.sin_addr );
	    
	    if (r == 0){

	    	g_message("DNS_resolver::run_queue: inet_aton failed");
	    	g_assert(0);
	    }
		
		// Si la cola no est'a bloqueada
		if (requests_queue->locked == FALSE) {
			
			if (requests_queue->cantidad > 1){
				
				// Bloquear la cola.
				requests_queue->locked = TRUE;
				
				struct dns_rq_t** tmp = &(requests_queue->items[0]);
				
				// Se recorre el arreglo de items de la cola hasta llegar al NULL final.
				while (*tmp != NULL) {
					
					//g_debug("DNS_resolver::run_queue: analizing item with id = %d",(*tmp)->unique_id);
					
					if ( (*tmp)->sended_time == 0 ) {	// Este item no se ha enviado nunca
					
						// Averiguar si el canal est'a en condici'on de recibir datos
						//cond = g_io_channel_get_buffer_condition(sock_DNS);
						
						//g_debug("cond = %u",cond);
						//g_debug("G_IO_OUT = %u",G_IO_OUT);
						
						//if ( (cond & G_IO_OUT) == G_IO_OUT) {
													
							g_debug("DNS_resolver::run_queue: sending the request of the item with id = %d",(*tmp)->unique_id);
							//r = write(g_io_channel_unix_get_fd(sock_DNS),(*tmp)->DNS_package,(*tmp)->size);
							//r = send(g_io_channel_unix_get_fd(sock_DNS),(*tmp)->DNS_package,(*tmp)->size,0);
							r = sendto (g_io_channel_unix_get_fd(sock_DNS),(*tmp)->DNS_package,(*tmp)->size,0,(struct sockaddr *)&remote_addr, sizeof(remote_addr));
							
							// Si la operaci'on de escritura fue correcta se marca el request como enviado poniendo en la variable sended_time
							// el tiempo actual. La pr'oxima vez que se corra la cola si no ha pasado el tiempo de timeout este rq no se enviar'a
							if (r != -1) (*tmp)->sended_time = time(NULL);
						//}
	
						// Se haya enviado o no el mensaje se sale de la funci'on. Dentro de 100 ms se vuelve a correr, si el mensaje se hab'ia enviado
						// sended_time est'a actualizado por lo tanto se va al pr'oximo item, sino se vuelve a intentar enviar este.
						requests_queue->locked = FALSE;
						return;
					}
					
					//if ( difftime(time(NULL), (*tmp)->sended_time) > CONFf("dns_timeout")){	// Si se cumpli'o el tiempo de time out se env'ia una
																							// respuesta vacia al solicitador y se elimina el item
																							// de la cola.
																							
					if ( difftime(time(NULL), (*tmp)->sended_time) > 30){
						
						g_debug("DNS_resolver::run_queue: timeout waiting for answer to the item with id = %d",(*tmp)->unique_id);
						
						struct respuesta *rp = g_new0(struct respuesta, 1);
						
						rp->pregunta = (unsigned char*)strdup((const char*)((*tmp)->name));
						rp->ip_addresses = g_new0(struct sockaddr_in*,1);
						rp->nombres = g_new0(unsigned char*,1);
						
						(*((*tmp)->du.return_function))(rp,(*tmp)->du.user_d);
						
						free_respuesta (rp);
						
						remove_from_queue(*tmp);
						requests_queue->locked = FALSE;
						return;	
					}
					tmp++;	// Si se lleg'o aqu'i fue porque a'un no se cumplido el timeout dns para el item, por lo tanto se sigue el recorrido de la
							// cola hacia el pr'oximo item.
				}
				requests_queue->locked = FALSE;
			}
		}
		else return;
	}

	void DNS_resolver::DNS_receive(unsigned char *buf1, guint size) {
		
		// Esta funci'on recibe los datos que llegaron a trav'es del canal DNS, parsea el mensaje, busca en la cola de request el que se
		// corresponde con esta respuesta y le responde a quien origin'o el request a trav'es de la funci'on que se registr'o al efecto en
		// la estructura dns_rq_t
		
		g_debug("DNS_resolver::DNS_receive: entering");
		
		unsigned char *buffer = g_new0(unsigned char,size + 2);
		memcpy(buffer,buf1,size);
		
		struct DNS_PACKAGE* full_dns_answer = parse_DNS_PACKAGE(buffer);
		
		if (requests_queue->locked == TRUE) {
			
			g_debug("DNS_resolver::DNS_receive: queue locked, posponing the processing of the message");
			// Si la cola est'a bloqueada se pospone para despu'es la busqueda del mensaje original.
			g_timeout_add(50, (GSourceFunc) return_request_delayed, full_dns_answer);
		}
		else {
			
			requests_queue->locked = TRUE;
			return_request(full_dns_answer);
			requests_queue->locked = FALSE;
		}
	return;
	}
	
	void DNS_resolver::return_request(struct DNS_PACKAGE* answer) {
		
		struct dns_rq_t** tmp = &(requests_queue->items[0]);
			
		// Se recorre el arreglo de items de la cola hasta llegar al NULL final.
		while (*tmp != NULL) {
			
			//g_debug("answer id = %d",answer->dns_header->id);
			//g_debug("analizando request with id = %d",tmp->unique_id);
			
			if ((*tmp)->unique_id == answer->dns_header->id) {	// Voala, encontramos la solicitud original
				
				//g_debug("encontrada la solicitud original");
				unsigned int respuestas_ip = 0;
				unsigned int respuestas_nombres = 0;
				
				// Las queries siempre son nombres:
				
				//for(unsigned int j = 0;j<answer->dns_header->q_count;j++) respuestas_nombres++;
				
				if ( answer->dns_queries[0]->qtype == T_PTR ) respuestas_nombres = answer->dns_header->ans_count;
				else {
					// El nombre de la respuesta siempre se cuenta como nombre, los datos de la respuesta se cuentan o como
					// direcci'on ip (si es de ese tipo) o como otro nombre.
					
					for(unsigned int j = 0;j<answer->dns_header->ans_count;j++){
						
						respuestas_nombres++;
						if (ntohs(answer->dns_answers[j]->resource->type) == 1)	respuestas_ip++;
						else respuestas_nombres++;
					}
				}
				//g_debug("nombres: %u",respuestas_nombres);
				//g_debug("ips: %u",respuestas_ip);
				
				struct respuesta *rp = g_new0(struct respuesta, 1);
				rp->pregunta = (unsigned char*) strdup((const char*)answer->dns_queries[0]->name);
				rp->ip_addresses = g_new0(struct sockaddr_in*,respuestas_ip + 1);
				rp->nombres = g_new0(unsigned char*,respuestas_nombres + 1);
				
				respuestas_ip = 0;
				respuestas_nombres = 0;
				struct sockaddr_in* tempo;
				
				/*for(unsigned int j = 0;j<answer->dns_header->q_count;j++) {
					
					rp->nombres[respuestas_nombres] = (unsigned char*)g_strdup((gchar*)answer->dns_queries[j]->name);
					respuestas_nombres++;
				}*/
				
				if ( answer->dns_queries[0]->qtype == T_PTR ) {
					
					for(unsigned int j = 0;j<answer->dns_header->ans_count;j++) {
						
						rp->nombres[j] = (unsigned char*)g_strdup((gchar*)answer->dns_answers[j]->rdata);
					}
				}
				else {
					
					for(unsigned int j = 0;j<answer->dns_header->ans_count;j++){
						
						rp->nombres[respuestas_nombres] = (unsigned char*)g_strdup((gchar*)answer->dns_answers[j]->name);
						respuestas_nombres++;
						
						if (ntohs(answer->dns_answers[j]->resource->type) == 1) {	// Esta respuesta es una ip
							
							tempo = g_new0(struct sockaddr_in,1);
							
							memcpy(&(tempo->sin_addr.s_addr),(long*)answer->dns_answers[j]->rdata,sizeof(uint32_t));
							rp->ip_addresses[respuestas_ip] = tempo;
							respuestas_ip++;	
						}
						else {
							
							rp->nombres[respuestas_nombres] = (unsigned char*)g_strdup((gchar*)answer->dns_answers[j]->rdata);
							respuestas_nombres++;
						}
					}
				}
				// Ya aqu'i se creo la estructura "respuesta" que se va a devolver a quien hizo la solicitud DNS original.
				// Se invoca entonces la funci'on callback
				
				(*(*tmp)->du.return_function)(rp,(*tmp)->du.user_d);
				
				// Eliminaci'on de la estructura respuesta.
				
				free_respuesta (rp);
				
				// Eliminaci'on de la solicitud original y quitarla de la cola
				
				remove_from_queue(*tmp);
				return;
			}
			tmp++;
		}
		// Si se lleg'o aqu'i es porque esa solicitud ya no estaba en la cola porque se le hab'ia vencido el tiempo.
		// Debo liberar la estructura DNS_PACKAGE con que se entr'o a esta funci'on.
		
		return;
	}

	void DNS_resolver::free_respuesta (struct respuesta* resp) {
		
		g_free(resp->pregunta);
		for (struct sockaddr_in** kk = &(resp->ip_addresses[0]); *kk != NULL;kk++) g_free(*kk);
		g_free(resp->ip_addresses);
		for (unsigned char** mm = &(resp->nombres[0]); *mm != NULL;mm++) g_free(*mm);
		g_free(resp->nombres);
		g_free(resp);
		return;
	}
	
	void DNS_resolver::remove_from_queue(struct dns_rq_t* rq) {
		
		g_free(rq);
				
		struct dns_rq_t** tmp1 = g_new0(struct dns_rq_t*,requests_queue->cantidad-1);
		
		unsigned int i = 0;
		for (struct dns_rq_t** tmp2 = &(requests_queue->items[0]);*tmp2 != NULL;tmp2++) {
			
			if (*tmp2 != rq) {
				
				tmp1[i] = *tmp2;
				i++;
			}
		}
		g_free(requests_queue->items);
		requests_queue->items = tmp1;
		requests_queue->cantidad--;
		return;
	}
	
	gboolean DNS_resolver::is_queue_locked() {
		
		return requests_queue->locked;
	}
	
	void DNS_resolver::lock_queue(gboolean status) {
		
		requests_queue->locked = status;
	}
	
#endif
