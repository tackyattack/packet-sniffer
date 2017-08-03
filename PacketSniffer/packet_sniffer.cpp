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

    
    print_ip(buffer, header->len);
    
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

#define MAC_ADDR_TYPE_DESTINATION    1
#define MAC_ADDR_TYPE_SOURCE         2
#define MAC_ADDR_TYPE_BSSID          3
#define MAC_ADDR_TYPE_RECEIVER       4
#define MAC_ADDR_TYPE_TRANSMITTER    5
#define MAC_ADDR_TYPE_NONE           6

#define MAC_FRAME_TYPE_CONTROL       1
#define MAC_FRAME_TYPE_MANAGEMENT    2
#define MAC_FRAME_TYPE_DATA          3


struct MAC_header_frame_control_t
{ // 2 bytes
    uint16_t fc_protocol_version:2;     // protocol version
    uint16_t fc_typeb1:1;               // type
    uint16_t fc_typeb2:1;               // type
    uint16_t fc_subtype:4;              // subtype
    uint16_t fc_toDS:1;                 // to DS flag
    uint16_t fc_fromDS:1;               // from DS flag
    uint16_t fc_moreFrag:1;             // more fragmentation
    uint16_t fc_retry:1;                // retry flag
    uint16_t fc_power_management:1;     // power management flag
    uint16_t fc_more_data:1;            // more data flag
    uint16_t fc_wep:1;                  // wep flag
    uint16_t fc_order:1;                // order flag
};

struct MAC_header_duration_t
{ // 2 bytes
    uint8_t duration_ID_b1;
    uint8_t duration_ID_b2;
};

struct MAC_header_address_t
{ // 4 octets
    uint8_t addr1[6];
    uint8_t addr1_type;
    
    uint8_t addr2[6];
    uint8_t addr2_type;
    
    uint8_t addr3[6];
    uint8_t addr3_type;
    
    uint8_t addr4[6];
    uint8_t addr4_type;
};

struct MAC_header_sequence_control_t
{ // 2 bytes
    uint8_t sequence_b1;
    uint8_t sequence_b2;
};

struct MAC_header_qos_control_t
{ // 2 bytes
    uint8_t duration_ID_b1;
    uint8_t duration_ID_b2;
};

struct MAC_header_ht_control_t
{ // 2 bytes
    uint8_t duration_ID_b1;
    uint8_t duration_ID_b2;
    uint8_t duration_ID_b3;
    uint8_t duration_ID_b4;
};

struct MAC_header_frame_t

{
    MAC_header_frame_control_t    frame_control;
    MAC_header_duration_t         duration_id;
    MAC_header_address_t          address;
    MAC_header_sequence_control_t sequence_control;
    MAC_header_qos_control_t      qos_control;
    MAC_header_ht_control_t       ht_control;
    
    uint8_t frame_type;
    u_char *frame_body_start;
};


// Address field table 802.11:
//------------------------------------------------------------------------
// To DS    From DS    Address 1    Address 2    Address 3    Address 4

//   0         0          Dest         Src         BSSID         N/A
//   0         1          Dest         BSSID       Src           N/A
//   1         0          BSSID        Src         Dest          N/A
//   1         1          Recv         Trans       Dest          Src
//------------------------------------------------------------------------

void set_MAC_header(MAC_header_frame_t *frame, const u_char *buffer)
{
    // radio tap format
    //-----------------
    // version       : 1 bytes
    // padding       : 1 bytes
    // header length : 2 bytes
    //-----------------
    
    uint16_t radio_tap_len = 0;
    
    memcpy(&radio_tap_len, buffer + 2, sizeof(radio_tap_len));
    
    u_char *MAC_offset = buffer + radio_tap_len; // skip radiotap
    
    memcpy(&(frame->frame_control), MAC_offset, sizeof(frame->frame_control)); // copy in the frame control
    
    // note : careful, in the docs format is b3b2
    if(!frame->frame_control.fc_typeb1 && !frame->frame_control.fc_typeb2)
    { // 0 0
        frame->frame_type = MAC_FRAME_TYPE_MANAGEMENT;
    }
    else if(frame->frame_control.fc_typeb1 && !frame->frame_control.fc_typeb2)
    { // 1 0
        frame->frame_type = MAC_FRAME_TYPE_CONTROL;
    }
    else if(!frame->frame_control.fc_typeb1 && frame->frame_control.fc_typeb2)
    { // 0 1
        frame->frame_type = MAC_FRAME_TYPE_DATA;
    }
    
    bool addr_4_present = false;
    
    // process only data frames for now (really the most important ones)
    if(frame->frame_type == MAC_FRAME_TYPE_DATA)
    {
        
        if(!frame->frame_control.fc_toDS && !frame->frame_control.fc_fromDS)
        { // 0 0
            memcpy(frame->address.addr1, MAC_offset + 2 + 2, 6);
            memcpy(frame->address.addr2, MAC_offset + 2 + 2 + 6, 6);
            memcpy(frame->address.addr3, MAC_offset + 2 + 2 + 6 + 6, 6);
            
            frame->address.addr1_type = MAC_ADDR_TYPE_DESTINATION;
            frame->address.addr2_type = MAC_ADDR_TYPE_SOURCE;
            frame->address.addr3_type = MAC_ADDR_TYPE_BSSID;
            frame->address.addr4_type = MAC_ADDR_TYPE_NONE;
            
           addr_4_present = false;
        }
        else if(!frame->frame_control.fc_toDS && frame->frame_control.fc_fromDS)
        { // 0 1
            memcpy(frame->address.addr1, MAC_offset + 2 + 2, 6);
            memcpy(frame->address.addr2, MAC_offset + 2 + 2 + 6, 6);
            memcpy(frame->address.addr3, MAC_offset + 2 + 2 + 6 + 6, 6);
            
            frame->address.addr1_type = MAC_ADDR_TYPE_DESTINATION;
            frame->address.addr2_type = MAC_ADDR_TYPE_BSSID;
            frame->address.addr3_type = MAC_ADDR_TYPE_SOURCE;
            frame->address.addr4_type = MAC_ADDR_TYPE_NONE;
            
            addr_4_present = false;
        }
        else if(frame->frame_control.fc_toDS && !frame->frame_control.fc_fromDS)
        { // 1 0
            memcpy(frame->address.addr1, MAC_offset + 2 + 2, 6);
            memcpy(frame->address.addr2, MAC_offset + 2 + 2 + 6, 6);
            memcpy(frame->address.addr3, MAC_offset + 2 + 2 + 6 + 6, 6);
            
            frame->address.addr1_type = MAC_ADDR_TYPE_BSSID;
            frame->address.addr2_type = MAC_ADDR_TYPE_SOURCE;
            frame->address.addr3_type = MAC_ADDR_TYPE_DESTINATION;
            frame->address.addr4_type = MAC_ADDR_TYPE_NONE;
            
            addr_4_present = false;
        }
        else if(frame->frame_control.fc_toDS && frame->frame_control.fc_fromDS)
        { // 1 1
            
            //The presence of the Address 4 field is determined by the setting of the To DS and From DS subfields of the Frame Control field
            
            memcpy(frame->address.addr1, MAC_offset + 2 + 2, 6);
            memcpy(frame->address.addr2, MAC_offset + 2 + 2 + 6, 6);
            memcpy(frame->address.addr3, MAC_offset + 2 + 2 + 6 + 6, 6);
            memcpy(frame->address.addr3, MAC_offset + 2 + 2 + 6 + 6 + 6 + 2, 6); // skip sequence bytes (2)
            
            frame->address.addr1_type = MAC_ADDR_TYPE_RECEIVER;
            frame->address.addr2_type = MAC_ADDR_TYPE_TRANSMITTER;
            frame->address.addr3_type = MAC_ADDR_TYPE_DESTINATION;
            frame->address.addr4_type = MAC_ADDR_TYPE_SOURCE;
            
            addr_4_present = true;
        }
        
        u_char *end_of_addr;
        u_char *seq_ptr;
        
        if(addr_4_present)
        {
            end_of_addr = MAC_offset + 2 + 2 + 6 + 6 + 6 + 2 + 6;
            seq_ptr = MAC_offset + 2 + 2 + 6 + 6 + 6;
        }
        else
        {
            end_of_addr = MAC_offset + 2 + 2 + 6 + 6 + 6;
            seq_ptr = MAC_offset + 2 + 2 + 6 + 6 + 6;
        }
        
        
        
        memcpy(frame->address.addr3, MAC_addr_start + 6 + 6 + 6 + 2, 6);
        
    }
    
}

void process_80211(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    // notes:
    
    // radio tap + WLAN (actual 802.11 frame)
    
    // packet will only contain the needed address bytes, frame and duration are the
    // only constants between packets
    
    printf("packet of length: %d\n",header->caplen);
    for(int i = 0; i < header->caplen; i++)
    {
        if(i%10 == 0) printf("\n");
        printf(" %02X ",buffer[i]);
    }
    printf("\n\n");
    
    MAC_header_frame_t MAC_header;
    set_MAC_header(&MAC_header,buffer);
    
    printf("MAC addr 1: %d\n",MAC_header.address.addr1_type);
    printf("MAC addr 2: %d\n",MAC_header.address.addr2_type);
    printf("MAC addr 3: %d\n",MAC_header.address.addr3_type);
    printf("MAC addr 4: %d\n",MAC_header.address.addr4_type);
    
    printf("\n\n");
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
    
    pcap_loop(pcap , -1, process_80211, NULL);
    
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
