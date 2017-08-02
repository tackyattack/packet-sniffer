//
//  packet_sniffer.cpp
//  PacketSniffer
//
//  Created by HENRY BERGIN on 8/2/17.
//  Copyright © 2017 Henry Bergin. All rights reserved.
//

#include "packet_sniffer.h"

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

void print_ip_header(const u_char *Buffer, int Size)
{
    cout << "enter" << endl;
    
    struct ip *iph = (struct ip *)(Buffer  + sizeof(struct ether_header) );
    
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->ip_src.s_addr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->ip_dst.s_addr;
    
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
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    struct ip *iph = (struct ip*)(buffer + sizeof(struct ether_addr));
    ++total;
    
    print_ip_header(buffer, header->len);
    
    switch ((unsigned int)iph->ip_p)
    {
        case 1:  //ICMP Protocol
            ++icmp;
            cout << "ICMP packet" << endl;
            break;
            
        case 2:  //IGMP Protocol
            ++igmp;
            cout << "IGMP packet" << endl;
            break;
            
        case 6:  //TCP Protocol
            ++tcp;
            cout << "TCP packet" << endl;
            break;
            
        case 17: //UDP Protocol
            ++udp;
            cout << "UDP packet" << endl;
            break;
            
        default: //Some Other Protocol like ARP etc.
            ++others;
            cout << "Other packet" << endl;
            break;
    }
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
    handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
    
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
