//
//  packet_sniffer.cpp
//  PacketSniffer
//
//  Created by HENRY BERGIN on 8/2/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//

#include "packet_sniffer.h"
#include "80211.h"

#include <iostream>

#include <stdio.h>

#include <sys/socket.h> // socket library
#include <sys/types.h>  // useful system types
#include <netinet/in.h> // contains internet address types
#include <arpa/inet.h>  // IPv4 address manipulation
#include <netdb.h>      // for hostnames (DNS)

#include <pcap/pcap.h>

#include <string.h>

using namespace std;

FILE *logfile;
struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;

#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header


void print_data(const u_char * data , int Size)
{
    
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            printf("         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    printf("%c",(unsigned char)data[j]); //if its a number or alphabet
                
                else printf("."); //otherwise print a dot
            }
            printf("\n");
        }
        
        if(i%16==0) printf("   ");
        printf(" %02X",(unsigned int)data[i]);
        
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++)
            {
                printf("   "); //extra spaces
            }
            
            printf("         ");
            
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                {
                    printf("%c",(unsigned char)data[j]);
                }
                else
                {
                    printf(".");
                }
            }
            
            printf( "\n" );
        }
    }
}

unsigned int print_ip(const u_char *Buffer, int Size)
{
    
    struct ip *iph = (struct ip *)(Buffer  + sizeof(struct ether_header) );
    
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->ip_src.s_addr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->ip_dst.s_addr;
    
    cout << "packet from: " << inet_ntoa(source.sin_addr) << " going to: " << inet_ntoa(dest.sin_addr) << endl;
    
    return 0;
    
    if(strstr(inet_ntoa(source.sin_addr),"192.168.2.96") != NULL ||  strstr(inet_ntoa(dest.sin_addr),"192.168.2.96") != NULL )
    {
        
        printf("\n");
        printf("IP Header\n");
        printf("   |-IP Version        : %d\n",(unsigned int)iph->ip_v);
        printf("   |-Type Of Service   : %d\n",(unsigned int)iph->ip_tos);
        printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->ip_len));
        printf("   |-Identification    : %d\n",ntohs(iph->ip_id));
        printf("   |-TTL      : %d\n",(unsigned int)iph->ip_ttl);
        printf("   |-Protocol : %d\n",(unsigned int)iph->ip_p);
        printf("   |-Checksum : %d\n",ntohs(iph->ip_sum));
        printf("   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
        printf("   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
        
        
        unsigned short iphdrlen = iph->ip_hl*4;
        int header_size = 0;
        
        switch ((unsigned int)iph->ip_p)
        {
            case 6:
            {
                //TCP Protocol
                struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ether_header));
                header_size =  sizeof(struct ether_header) + iphdrlen + tcph->th_off*4;
                break;
            }
            case 17:
            {
                //UDP Protocol
                struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ether_header));
                header_size =  sizeof(struct ether_header) + iphdrlen + sizeof udph;
                break;
            }
        }
        
        print_data(Buffer + header_size, Size - header_size);
        
        return (unsigned int)iph->ip_p;
        
    }
    else
    {
        return 0;
    }
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{

    process_80211(buffer, header->caplen);
    
//    print_ip(buffer, header->len);
//    
//    switch (print_ip(buffer, header->len))
//    {
//        case 1:  //ICMP Protocol
//            ++icmp;
//            cout << "ICMP packet" << endl;
//            break;
//            
//        case 2:  //IGMP Protocol
//            ++igmp;
//            cout << "IGMP packet" << endl;
//            break;
//            
//        case 6:  //TCP Protocol
//            ++tcp;
//            cout << "TCP packet" << endl;
//            break;
//            
//        case 17: //UDP Protocol
//            ++udp;
//            cout << "UDP packet" << endl;
//            break;
//            
//        default: //Some Other Protocol like ARP etc.
//            ++others;
//            cout << "Other packet" << endl;
//            break;
//    }
    
}

void start_monitor_sniffer()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    //char filter[] = "type mgt subtype probe-req";
    char dev[] = "en0";
    //struct bpf_program fp;
    pcap_t *pcap = pcap_create(dev,errbuf);
    pcap_set_rfmon(pcap, 1);
    pcap_set_snaplen(pcap, 2048);
    pcap_set_promisc(pcap, 1);
    pcap_set_timeout(pcap, 512);
    
    int status;
    status = pcap_activate(pcap);
    //status = pcap_compile(pcap, &fp, filter, 0, 0);
    //status = pcap_setfilter(pcap, &fp);
    
    pcap_loop(pcap , -1, process_packet, NULL);
    
}

void start_sniffer()
{
    pcap_if_t *alldevsp , *device;
    pcap_t *handle; //Handle of the device that shall be sniffed
    
    char errbuf[100] , *devname , devs[100][100];
    int count = 1 , n;
    
    //First get the list of available devices
    printf("Finding available devices ... ");
    if( pcap_findalldevs( &alldevsp , errbuf) )
    {
        printf("Error finding devices : %s" , errbuf);
        return;
    }
    printf("Done");
    
    //Print the available devices
    printf("\nAvailable Devices are :\n");
    for(device = alldevsp ; device != NULL ; device = device->next)
    {
        printf("%d. %s - %s\n" , count , device->name , device->description);
        if(device->name != NULL)
        {
            strcpy(devs[count] , device->name);
        }
        count++;
    }
    
    //Ask user which device to sniff
    printf("Enter the number of the device you want to sniff : ");
    scanf("%d" , &n);
    devname = devs[n];
    
    //Open the device for sniffing
    printf("Opening device %s for sniffing ... " , devname);
    handle = pcap_open_live(devname , 65536 , 1 , 1000 , errbuf); // promiscuous mode, and 1 sec timeout (should be nonzero otherwise it'll
                                                                  // wait until a large amount have arrived)

    int mon_can_ret = pcap_can_set_rfmon(handle);
    
    cout << "monitor capability: " << mon_can_ret << endl;
    
    int mon_ret = pcap_set_rfmon(handle, 1);
    
    if(mon_ret != 0)
    {
        cout << "monitor mode error" << endl;
    }
    
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
        return;
    }
    printf("Done\n");
    
    logfile=fopen("log.txt","w");
    if(logfile==NULL)
    {
        printf("Unable to create file.");
    }
    
    
    //Put the device in sniff loop
    pcap_loop(handle , -1 , process_packet , NULL);
}
