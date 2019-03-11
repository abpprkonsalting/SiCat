# include "dns.h"

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
	for(int i=0;i<(int)strlen((const char*)name);i++) 
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

struct DNS_PACKAGE* parse_DNS_message(char* payload, int payload_size){
	
	struct DNS_PACKAGE* DNSpackage;
	gchar ip[16];
	unsigned char* begining;
	unsigned int total;
	//struct RES_RECORD answers[20],auth[20],addit[20]; //the replies from the DNS server
	int stop;
	
	// Parsing del datagrama IP completo a la estructura DNSpackage, la cual incluye todo el paquete IP.
	
	DNSpackage = g_new0(struct DNS_PACKAGE,1);
	
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
	total = DNSpackage->dns_message_size - sizeof(struct DNS_HEADER);
	
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

void free_DNS_message(struct DNS_PACKAGE* DNSpackage){
	
	/*for(int i=0;i<ntohs(DNSpackage->dns_header->add_count);i++){
		
		g_free(DNSpackage->dns_aditionals[i]->name);
		g_free(DNSpackage->dns_aditionals[i]->rdata);
		g_free(DNSpackage->dns_aditionals[i]);
	}
	for(int i=0;i<ntohs(DNSpackage->dns_header->auth_count);i++){
		
		g_free(DNSpackage->dns_authorities[i]->name);
		g_free(DNSpackage->dns_authorities[i]->rdata);
		g_free(DNSpackage->dns_authorities[i]);
	}
	*/
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
