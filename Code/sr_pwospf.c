/*-----------------------------------------------------------------------------
 * file: sr_pwospf.c
 * date: Tue Nov 23 23:24:18 PST 2004
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include "sr_pwospf.h"
#include "sr_router.h"
#include "pwospf_protocol.h"
#include "sr_protocol.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_utils.h"

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* -- declaration of main thread function for pwospf subsystem --- */
static void *pwospf_run_thread(void *arg);
static void *pwospf_run_thread_lsu(void *arg);
void sendHelloPacket(struct sr_instance *sr, struct sr_if *iface);
void send_hello_to_all_interfaces(struct sr_instance *sr);
void send_all_lsu_updates(struct sr_instance *sr);
uint8_t send_to_all_peeps[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                             0xFF};
void sendupdatePacket(struct sr_instance *sr, struct sr_rt *rtable, struct neighbor *neigh);

/*---------------------------------------------------------------------
 * Method:add_if_to_rt()
 *find the add if enteries to rt

 *---------------------------------------------------------------------*/
void add_if_to_rt(struct sr_instance *sr)
{
    struct in_addr ip_addr;
    struct in_addr mask_addr;
    struct in_addr gw;

    struct sr_if *if_walker = sr->if_list;
    ;

    if (sr->if_list == 0)
    {
        printf(" Interface list empty \n");
        return;
    }

    if_walker = sr->if_list;
    ip_addr.s_addr = if_walker->ip;
    mask_addr.s_addr = if_walker->mask;
    gw.s_addr = 0;
    u_int16_t cost = 1; // starting cost = 1
    sr_add_rt_entry(sr, ip_addr, gw, mask_addr, if_walker->name, cost);
    while (if_walker->next)
    {
        if_walker = if_walker->next;

        ip_addr.s_addr = if_walker->ip;
        mask_addr.s_addr = if_walker->mask;

        sr_add_rt_entry(sr, ip_addr, gw, mask_addr, if_walker->name, cost);
    }

    sr_print_routing_table(sr);
}

/*---------------------------------------------------------------------
 * Method: pwospf_init(..)
 *
 * Sets up the internal data structures for the pwospf subsystem
 *
 * You may assume that the interfaces have been created and initialized
 * by this point.
 *---------------------------------------------------------------------*/

int pwospf_init(struct sr_instance *sr)
{
    assert(sr);

    sr->ospf_subsys = (struct pwospf_subsys *)malloc(sizeof(struct
                                                            pwospf_subsys));

    assert(sr->ospf_subsys);
    pthread_mutex_init(&(sr->ospf_subsys->lock), 0);
    if (sr->routing_table == 0)
    {
        printf("\n adding iface values to routing table\n");
        add_if_to_rt(sr);
    }

    /* -- handle subsystem initialization here! -- */

    /* -- start thread subsystem -- */
    if (pthread_create(&sr->ospf_subsys->thread, 0, pwospf_run_thread, sr))
    {
        perror("pthread_create");
        assert(0);
    }
    /* -- start thread subsystem -- */
    if (pthread_create(&sr->ospf_subsys->thread, 0, pwospf_run_thread_lsu, sr))
    {
        perror("pthread_create");
        assert(0);
    }
    return 0; /* success */
} /* -- pwospf_init -- */

/*---------------------------------------------------------------------
 * Method: pwospf_lock
 *
 * Lock mutex associated with pwospf_subsys
 *
 *---------------------------------------------------------------------*/

void pwospf_lock(struct pwospf_subsys *subsys)
{
    if (pthread_mutex_lock(&subsys->lock))
    {
        assert(0);
    }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_unlock
 *
 * Unlock mutex associated with pwospf subsystem
 *
 *---------------------------------------------------------------------*/

void pwospf_unlock(struct pwospf_subsys *subsys)
{
    if (pthread_mutex_unlock(&subsys->lock))
    {
        assert(0);
    }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_run_thread
 *
 * Main thread of pwospf subsystem.
 *
 *---------------------------------------------------------------------*/

static void *pwospf_run_thread(void *arg)
{
    struct sr_instance *sr = (struct sr_instance *)arg;

    while (1)
    {
        /* -- PWOSPF subsystem functionality should start  here! -- */

        pwospf_lock(sr->ospf_subsys);
        printf(" pwospf subsystem sleeping \n");
        send_hello_to_all_interfaces(sr);
        if (sr->main_neighbor || sr->side_neighbor) // atleast one neighbor is connected
        {
            send_all_lsu_updates(sr);
        }
        pwospf_unlock(sr->ospf_subsys);
        sleep(OSPF_DEFAULT_HELLOINT);
        printf(" pwospf subsystem awake \n");
    };
    return NULL;
} /* -- run_ospf_thread -- */

/*---------------------------------------------------------------------
 * Method: pwospf_run_thread_lsu
 *
 * side thread of pwospf subsystem.
 * Removes enteries from the routing table for a failed link.
 *---------------------------------------------------------------------*/

static void *pwospf_run_thread_lsu(void *arg)
{
    struct sr_instance *sr = (struct sr_instance *)arg;

    while (1)
    {
        /* -- PWOSPF subsystem functionality should start  here! -- */
        sleep(OSPF_NEIGHBOR_TIMEOUT);
        pwospf_lock(sr->ospf_subsys);
        printf(" pwospf lsu subsystem sleeping \n");
        time_t time_c;
        time(&time_c);
        uint32_t diff = (uint32_t)time_c;
        if (sr->main_neighbor)
        {
            diff = diff - sr->main_neighbor->time;
            if (diff > OSPF_NEIGHBOR_TIMEOUT)
            {
                printf("timeout spotted for main neighbor\n");
                sr_remove_rt_entries(sr, sr->main_neighbor->sip);
            }
        }
        if (sr->side_neighbor)
        {
            diff = (uint32_t)time_c;
            diff = diff - sr->side_neighbor->time;
            if (diff > OSPF_NEIGHBOR_TIMEOUT)
            {
                printf("timeout spotted for side neighbor\n");
                sr_remove_rt_entries(sr, sr->side_neighbor->sip);
            }
        }
        sr_print_routing_table(sr);

        pwospf_unlock(sr->ospf_subsys);
        printf(" pwospf lsu subsystem awake \n");
    };
    return NULL;
} /* -- run_ospf_thread -- */
/*---------------------------------------------------------------------
 * Method: send_hello_to_all_interfaces
 *
 * Sends hello OSPF messages to all the connected neighbors
 *---------------------------------------------------------------------*/

void send_hello_to_all_interfaces(struct sr_instance *sr)
{

    struct sr_if *if_walker = 0;

    if (sr->if_list == 0)
    {
        printf(" Interface list empty \n");
        return;
    }

    if_walker = sr->if_list;
    sendHelloPacket(sr, sr->if_list);
    while (if_walker->next)
    {
        if_walker = if_walker->next;
        sendHelloPacket(sr, if_walker);
    }
}
/*---------------------------------------------------------------------
 * Method: send_all_lsu_updates
 *
 * Sends routing table entries' OSPF messages to all the connected neighbors
 *---------------------------------------------------------------------*/
void send_all_lsu_updates(struct sr_instance *sr)
{
    struct sr_rt *rt_walker = 0;
    if (sr->routing_table == 0)
    {
        printf(" Routing Table empty, no updates to send  \n");
        return;
    }
    rt_walker = sr->routing_table;
    if (sr->main_neighbor)
        sendupdatePacket(sr, rt_walker, sr->main_neighbor);
    if (sr->side_neighbor)
        sendupdatePacket(sr, rt_walker, sr->side_neighbor);

    while (rt_walker->next)
    {
        rt_walker = rt_walker->next;
        if (sr->main_neighbor)
            sendupdatePacket(sr, rt_walker, sr->main_neighbor);
        if (sr->side_neighbor)
            sendupdatePacket(sr, rt_walker, sr->side_neighbor);
    }
}
/*---------------------------------------------------------------------
 * Method: sendHelloPacket
 *
 * Sends sends a ospf hello packet
 *---------------------------------------------------------------------*/

void sendHelloPacket(struct sr_instance *sr, struct sr_if *iface)
{
    uint32_t len = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr);

    // defining IP header
    uint8_t *new_packet = malloc(len);
    check_malloc_error(new_packet);
    struct sr_ethernet_hdr *eth_head = (struct sr_ethernet_hdr *)(new_packet);

    uint16_t ether_type = htons(ETHERTYPE_IP);
    eth_head->ether_type = ether_type;

    memcpy(&eth_head->ether_shost, iface->addr, ETHER_ADDR_LEN);
    memcpy(&eth_head->ether_dhost, send_to_all_peeps, ETHER_ADDR_LEN);

    struct ip *ip_header_reply = (struct ip *)(new_packet + sizeof(struct sr_ethernet_hdr));
    struct in_addr dst, src;

    dst.s_addr = htonl(OSPF_AllSPFRouters);
    uint32_t send_ip = iface->ip;
    src.s_addr = (send_ip);

    uint32_t r_id = sr->if_list->ip;

    // standard values
    ip_header_reply->ip_p = 89; // OSPF protocol number
    ip_header_reply->ip_sum = 0;
    ip_header_reply->ip_len = htons(len - sizeof(struct sr_ethernet_hdr));
    ip_header_reply->ip_id = htons(0);
    ip_header_reply->ip_off = 0;
    ip_header_reply->ip_v = 4;
    ip_header_reply->ip_hl = 5;
    ip_header_reply->ip_tos = 0;
    ip_header_reply->ip_ttl = 64;
    ip_header_reply->ip_src = src;
    ip_header_reply->ip_dst = dst;
    ip_header_reply->ip_sum = cksum(new_packet + sizeof(struct sr_ethernet_hdr),
                                    sizeof(struct ip));

    // standard OSPFv2 HELLO packet
    struct ospfv2_hdr *ospf_hdr = (struct ospfv2_hdr *)(new_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
    memset(ospf_hdr, 0, sizeof(struct ospfv2_hdr));
    ospf_hdr->version = 2;
    ospf_hdr->type = OSPF_TYPE_HELLO;
    ospf_hdr->len = htons(sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr));
    ospf_hdr->rid = (r_id);
    ospf_hdr->aid = (0);
    ospf_hdr->csum = (0);
    ospf_hdr->autype = (OSPF_DEFAULT_AUTHKEY);
    ospf_hdr->csum = (cksum(new_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip), sizeof(struct ospfv2_hdr) - sizeof(uint64_t)));
    ospf_hdr->audata = (0);
    if (sr->main_router)
    {
        ospf_hdr->audata = 1;
    }

    struct ospfv2_hello_hdr *hello_hdr = (struct ospfv2_hello_hdr *)(new_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr));
    memset(hello_hdr, 0, sizeof(struct ospfv2_hello_hdr));
    hello_hdr->nmask = (iface->mask); // Replace with your netmask
    hello_hdr->helloint = htons(OSPF_DEFAULT_HELLOINT);

    int ret = sr_send_packet(sr, new_packet, len, iface->name);
    if (new_packet)
        free(new_packet);
    printf("\nretval of ospf hello packet sent: %d and len: %d\n", ret, len);
}
/*---------------------------------------------------------------------
 * Method: sendupdatePacket
 *
 * Sends sends a lsu update
 *---------------------------------------------------------------------*/

void sendupdatePacket(struct sr_instance *sr, struct sr_rt *rtable, struct neighbor *neigh)
{

    uint32_t len = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr) + sizeof(struct ospfv2_lsu_hdr) + sizeof(struct ospfv2_lsu);

    // defining IP header
    struct sr_if *iface_to_main = sr_get_interface(sr, neigh->interface);

    uint8_t *new_packet = malloc(len);
    check_malloc_error(new_packet);

    struct sr_ethernet_hdr *eth_head = (struct sr_ethernet_hdr *)(new_packet);

    uint16_t ether_type = htons(ETHERTYPE_IP);
    eth_head->ether_type = ether_type;

    memcpy(&eth_head->ether_shost, iface_to_main->addr, ETHER_ADDR_LEN);
    memcpy(&eth_head->ether_dhost, send_to_all_peeps, ETHER_ADDR_LEN);

    struct ip *ip_header_reply = (struct ip *)(new_packet + sizeof(struct sr_ethernet_hdr));
    struct in_addr dst, src;

    dst.s_addr = htonl(OSPF_AllSPFRouters);
    uint32_t send_ip = iface_to_main->ip;

    src.s_addr = (send_ip);

    uint32_t r_id = sr->if_list->ip;
    // standard values
    ip_header_reply->ip_p = 89;
    ip_header_reply->ip_sum = 0;
    ip_header_reply->ip_len = htons(len - sizeof(struct sr_ethernet_hdr));
    ip_header_reply->ip_id = htons(0);
    ip_header_reply->ip_off = 0;
    ip_header_reply->ip_v = 4;
    ip_header_reply->ip_hl = 5;
    ip_header_reply->ip_tos = 0;
    ip_header_reply->ip_ttl = 64;
    ip_header_reply->ip_src = src;
    ip_header_reply->ip_dst = dst;
    ip_header_reply->ip_sum = cksum(new_packet + sizeof(struct sr_ethernet_hdr),
                                    sizeof(struct ip));

    // standard OSPFv2 HELLO packet
    struct ospfv2_hdr *ospf_hdr = (struct ospfv2_hdr *)(new_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
    memset(ospf_hdr, 0, sizeof(struct ospfv2_hdr));
    ospf_hdr->version = 2;
    ospf_hdr->type = OSPF_TYPE_LSU;
    ospf_hdr->len = htons(sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr));
    ospf_hdr->rid = (r_id);
    ospf_hdr->aid = (0);
    ospf_hdr->csum = (0);
    ospf_hdr->autype = (OSPF_DEFAULT_AUTHKEY);
    ospf_hdr->csum = (cksum(new_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip), sizeof(struct ospfv2_hdr) - sizeof(uint64_t)));
    ospf_hdr->audata = (0);

    struct ospfv2_hello_hdr *hello_hdr = (struct ospfv2_hello_hdr *)(new_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr));
    memset(hello_hdr, 0, sizeof(struct ospfv2_hello_hdr));
    hello_hdr->nmask = (rtable->mask.s_addr);
    hello_hdr->helloint = htons(OSPF_DEFAULT_HELLOINT);

    struct ospfv2_lsu_hdr *lsu_hdr = (struct ospfv2_lsu_hdr *)(new_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr));
    memset(lsu_hdr, 0, sizeof(struct ospfv2_lsu_hdr));
    lsu_hdr->seq = (1);
    lsu_hdr->ttl = (1);
    lsu_hdr->num_adv = (rtable->cost); // used to represent cost for DV algorithm

    // standard LSU advertisement
    struct ospfv2_lsu *lsu_adv = (struct ospfv2_lsu *)(new_packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr));
    lsu_adv->subnet = (rtable->dest.s_addr);
    lsu_adv->mask = (rtable->mask.s_addr);
    lsu_adv->rid = (sr->if_list->ip);

    printf("LSU subnet Address: %s\n", inet_ntoa(src));

    int ret = sr_send_packet(sr, new_packet, len, neigh->interface);
    if (new_packet)
        free(new_packet);
    printf("\nretval of ospf lsu packet sent: %d and len: %d\n", ret, len);
}