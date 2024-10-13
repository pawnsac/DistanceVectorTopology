/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *  
 * #1693354266
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#ifdef VNL
#include "vnlconn.h"
#endif

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* ----------------------------------------------------------------------------
 * struct neighbors
 *
 * features of the neighbor to be added
 *
 * -------------------------------------------------------------------------- */

struct neighbor
{
    uint32_t rid;
    uint32_t sip;
    uint32_t nmask;
    uint32_t time;
    char* interface;    
};

/* ----------------------------------------------------------------------------
 * struct buffer_ip_packet
 *
 * IP Cache is handled in this struct
 *
 * -------------------------------------------------------------------------- */

struct buffer_ip_packet
{
    // packet to be buffered
    uint32_t ip;
    unsigned short len;
    uint8_t* packet;
    struct buffer_ip_packet * next;
};

/* ----------------------------------------------------------------------------
 * struct sr_cache_arp
 *
 * ARP Cache is handled in this struct
 *
 * -------------------------------------------------------------------------- */

struct sr_cache_arp
{
    uint32_t ip; // IP address 
    uint8_t  addr[ETHER_ADDR_LEN]; // Ethernet address 
    uint32_t time; // time
    struct sr_cache_arp*  next;
};

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */


/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
#ifdef VNL
    struct VnlConn* vc;
#endif
    char user[32]; /* user name */
    char host[32]; /* host name */
    char template[30]; /* template name if any */
    char auth_key_fn[64]; /* auth key filename */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    FILE* logfile;
    struct sr_cache_arp* cache; /* arp cache */
    struct buffer_ip_packet* buffer; /* ip packets buffer */
    uint16_t main_router;
    uint16_t active;
    struct neighbor* main_neighbor; 
    struct neighbor* side_neighbor;


    /* -- pwospf subsystem -- */
    struct pwospf_subsys* ospf_subsys;

};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */
