#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // exit()
#include<string.h> 
#include<sys/socket.h>
#include<arpa/inet.h> // inet_ntoa()
#include<net/ethernet.h>  //ethernet header
#include<netinet/tcp.h>   //tcp header
#include<netinet/ip.h>    //ip header
  
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void process_ip_packet(const u_char * , int);
void print_ethernet_packet(const u_char * , int);//print
void print_ip_packet(const u_char * , int);
void print_tcp_packet(const u_char *  , int );
void Print_data (const u_char * , int);
 

struct sockaddr_in source,dest;
 
int main()
{
    pcap_if_t *alldevsp , *device;
    pcap_t *handle;
 
    char errbuf[100] , *devname; 
    int count = 1 , n;

    devname = pcap_lookupdev(errbuf);//get the list of device
    if(devname == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("\nDevice Name : %s\n",devname);

    handle = pcap_open_live(devname, 65536, 1, 0, errbuf);
    //get packet capture descriptor of devic3

    if (handle == NULL)
    {
        printf("Error!! : %s\n", errbuf);
        exit(1);
    }     

    printf("\n======================Success!!==============================\n");

    //Put the device in sniff loop
    pcap_loop(handle , -1, process_packet , NULL);
     
    return 0;  
}
 
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int size = header->len;
     
    //Get IP ,exclude ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    
    switch (iph->protocol) //Check the Protocol type
    {
        case 1:  //ICMP Protocol
	    print_ip_packet(buffer , size);
	    printf("\nThis is ICMP protocol\n");
            printf("===================================================");
            break;
         
        case 6:  //TCP Protocol
            print_tcp_packet(buffer , size);
            break;
         
        case 17: //UDP Protocol
	    print_ip_packet(buffer , size);
	    printf("\nThis is UDP protocol\n");
	    printf("===================================================");
            break;
         
        default: //Other Protocol
            break;
    }
}
 
void print_ethernet_packet(const u_char *Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;
     
    printf( "\n");
    printf( "\nEthernet Header\n");
    printf( "\tDestination Address : %.2X %.2X %.2X %.2X %.2X %.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    printf( "\tSource Address      : %.2X %.2X %.2X %.2X %.2X %.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
}
 
void print_ip_packet(const u_char * Buffer, int Size)
{
    print_ethernet_packet(Buffer , Size);
   
    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    printf( "\n");
    printf( "IP Header\n");
    printf( "\tSource IP        : %s\n" , inet_ntoa(source.sin_addr) );
    printf( "\tDestination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
}
 
void print_tcp_packet(const u_char * Buffer, int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
             
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

    print_ip_packet(Buffer,Size);
         
    printf( "\n");
    printf( "TCP Header\n");
    printf( "\tSource Port      : %.4x\n",ntohs(tcph->source));
    printf( "\tDestination Port : %.4x\n",ntohs(tcph->dest));
    printf( "\n");

    printf( "Data\n");   
    Print_data(Buffer + header_size , Size - header_size );
                         
    printf( "\n==========================================================");
}
  
void Print_data (const u_char * data , int Size)
{

    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if(i%16==0) printf("\n   ");
        printf( " %02X",(unsigned int)data[i]);
    }

}
