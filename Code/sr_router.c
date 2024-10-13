/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 * #1693354266
 *
 **********************************************************************/

#include "sr_if.h"
#include "sr_protocol.h"
#include "pwospf_protocol.h"
#include "sr_utils.h"
#include "sr_pwospf.h"

#include "sr_router.h"
#include "sr_rt.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


/*---------------------------------------------------------------------
 * Method:add_lsu_to_rt
 * update routing table based on lsu update.
 * Itimplements  the following formula:
 * cost(i,dest)=min(cost(i,j)+cost(j,dest), cost(i,dest))
 *---------------------------------------------------------------------*/
void add_lsu_to_rt(struct sr_instance *sr, uint8_t *packet, char *interface)
{
	struct ip *ip_packet = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));
	struct in_addr send_ip = ip_packet->ip_src;
	struct ospfv2_lsu_hdr *lsu_hdr = (struct ospfv2_lsu_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr));
	struct ospfv2_lsu *lsu_adv = (struct ospfv2_lsu *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr));
	struct in_addr ip_addr;
	struct in_addr mask_addr;
	struct in_addr gw = send_ip;
	uint16_t cost=lsu_hdr->num_adv + 1; // used to represent the link cost for neighbor

	ip_addr.s_addr = lsu_adv->subnet;
	mask_addr.s_addr = lsu_adv->mask;
	printf("LSU IP Address: %s\n", inet_ntoa(ip_addr));
	printf("LSU Subnet Mask: %s\n", inet_ntoa(mask_addr));
	printf("LSU Gateway: %s\n", inet_ntoa(gw));

	sr_add_rt_entry(sr, ip_addr, gw, mask_addr, interface,cost);
	sr_print_routing_table(sr);

	return;
}

/*---------------------------------------------------------------------
 * Method:add_neighbor
 * add the neighbors enteries. These will be used to make the decisions
 * about updating the routing table.
 *---------------------------------------------------------------------*/

void add_neighbor(struct sr_instance *sr, uint8_t *packet, char *interface)
{
	struct ip *ip_packet = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));

	struct ospfv2_hdr *ospf_header = (struct ospfv2_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
	struct ospfv2_hello_hdr *hello_header = (struct ospfv2_hello_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr));
	struct neighbor *n;
	struct in_addr r;
	r.s_addr = ospf_header->rid;

	struct in_addr send_ip = ip_packet->ip_src;

	if (!sr->main_router)
	{
		if (ospf_header->audata)
		{
			sr->active = 1;
			time_t current_time;
			time(&current_time);
			n = malloc(sizeof(struct neighbor));
			check_malloc_error(n);
			n->rid = ospf_header->rid;
			n->sip = ip_packet->ip_src.s_addr;
			n->nmask = hello_header->nmask;
			n->interface = strdup(interface);
			n->time = (uint32_t)current_time;
			sr->main_neighbor = n;
			printf("\n adding entry with ip %s to  main neighbor", inet_ntoa(r));
			printf("\n time of additon %u to main neighbor\n", n->time);
		}
		else
		{
			time_t current_time;
			time(&current_time);
			n = malloc(sizeof(struct neighbor));
			check_malloc_error(n);
			n->rid = ospf_header->rid;
			n->sip = ip_packet->ip_src.s_addr;
			n->nmask = hello_header->nmask;
			n->interface = strdup(interface);
			n->time = (uint32_t)current_time;
			sr->side_neighbor = n;

			printf("\n adding entry with ip %s to side neighbor\n", inet_ntoa(r));
			printf("\n time of additon %u to side neighbor\n", n->time);
		}
	}

	else
	{
		sr->active = 1;
		if (sr->main_neighbor && sr->side_neighbor)
		{
			time_t current_time;
			time(&current_time);
			n = malloc(sizeof(struct neighbor));
			check_malloc_error(n);
			n->rid = ospf_header->rid;
			n->sip = ip_packet->ip_src.s_addr;
			n->nmask = hello_header->nmask;
			n->interface = strdup(interface);
			n->time = (uint32_t)current_time;
			if (sr->side_neighbor->rid == n->rid)
			{
				sr->side_neighbor = n;
			}
			else
			{
				sr->main_neighbor = n;
			}
			printf("\n as main neighbor adding entry with ip %s to  neighbor\n", inet_ntoa(r));
			printf("\n as main neighbor time of additon %u to  neighbor\n", n->time);
		}
		else
		{

			time_t current_time;
			time(&current_time);
			n = malloc(sizeof(struct neighbor));
			check_malloc_error(n);
			n->rid = ospf_header->rid;
			n->sip = ip_packet->ip_src.s_addr;
			n->nmask = hello_header->nmask;
			n->interface = strdup(interface);
			n->time = (uint32_t)current_time;
			if (sr->main_neighbor)
			{
				sr->side_neighbor = n;
			}
			else
			{
				sr->main_neighbor = n;
			}
			printf("\n as main neighbor adding entry with ip %s to  neighbor\n", inet_ntoa(r));
			printf("\n as main neighbor time of additon %u to  neighbor\n", n->time);
		}
	}

	printf("\n sending ip %s\n", inet_ntoa(send_ip));
}
/*---------------------------------------------------------------------
 * Method: add_to_buff
 * add ip packet to buffer
 *---------------------------------------------------------------------*/
void add_to_buff(struct sr_instance *sr, uint8_t *packet, unsigned int len,
				 uint32_t next_hop_ip)
{
	struct buffer_ip_packet *buff_walker;
	uint8_t i;

	printf("\nto add buff ip: %u\n", next_hop_ip);
	printf("\npacket len: %u\n", len);

	buff_walker = sr->buffer;
	if (buff_walker == NULL)
	{
		sr->buffer = malloc(sizeof(struct buffer_ip_packet));
		check_malloc_error(sr->buffer);
		sr->buffer->ip = next_hop_ip;
		sr->buffer->len = len;
		sr->buffer->packet = malloc(len);
		check_malloc_error(sr->buffer->packet);
		memcpy(sr->buffer->packet, packet, len);
		sr->buffer->next = NULL;
		printf("\nadded to buff\n");
	}
	else
	{
		i = 1;
		while (1)
		{
			if (buff_walker->next == NULL)
			{
				printf("\nAdded to buff count: %u\n", i);
				buff_walker->next = malloc(sizeof(struct buffer_ip_packet));
				check_malloc_error(buff_walker->next);
				buff_walker = buff_walker->next;
				buff_walker->ip = next_hop_ip;
				buff_walker->len = len;
				buff_walker->packet = malloc(len);
				check_malloc_error(buff_walker->packet);
				memcpy(buff_walker->packet, packet, len);
				buff_walker->next = NULL;
				break;
			}
			i += 1;
			buff_walker = buff_walker->next;
		}
	}
}

uint8_t send_to_all[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
									   0xFF};
uint8_t arp_header_len = 42;
/*---------------------------------------------------------------------
 * Method: make_and_send_ip_request
 * send the ip packet
 *---------------------------------------------------------------------*/
void make_and_send_ip_request(struct sr_instance *sr, uint8_t *packet,
							  unsigned int len, char *interface)
{
	uint8_t *new_packet = malloc(len);
	check_malloc_error(new_packet);
	memcpy(new_packet, packet, len);

	struct sr_ethernet_hdr *eth_head = (struct sr_ethernet_hdr *)(new_packet);
	struct ip *ip_header = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));

	uint16_t ether_type = htons(ETHERTYPE_IP);
	eth_head->ether_type = ether_type;

	struct ip *ip_header_reply = (struct ip *)(new_packet + sizeof(struct sr_ethernet_hdr));

	ip_header_reply->ip_p = ip_header->ip_p;
	ip_header_reply->ip_sum = 0;
	ip_header_reply->ip_len = htons(len - sizeof(struct sr_ethernet_hdr));
	ip_header_reply->ip_id = htons(ip_header->ip_id);
	ip_header_reply->ip_off = 0;
	ip_header_reply->ip_v = 4;
	ip_header_reply->ip_hl = 5;
	ip_header_reply->ip_tos = ip_header->ip_tos;
	ip_header_reply->ip_ttl = ip_header->ip_ttl;

	ip_header_reply->ip_src = ip_header->ip_src;
	ip_header_reply->ip_dst = ip_header->ip_dst;
	ip_header_reply->ip_sum = cksum(new_packet + sizeof(struct sr_ethernet_hdr),
									sizeof(struct ip));
	printf("Sending reply IP packet:\n");
	printf("Source IP: %s\n", inet_ntoa(ip_header_reply->ip_src));
	printf("Destination IP: %s\n", inet_ntoa(ip_header_reply->ip_dst));

	int ret = sr_send_packet(sr, new_packet, len, interface);
	if (new_packet)
		free(new_packet);
	printf("\nretval of ip packet sent: %d\n", ret);
}

/*---------------------------------------------------------------------
 * Method: make_and_send_arp_request
 * send the packet request mac address for the target ip
 *---------------------------------------------------------------------*/
void make_and_send_arp_request(struct sr_instance *sr, uint32_t target_ip,
							   unsigned int len, char *interface)
{
	struct sr_if *iface;
	uint8_t *new_packet;
	struct sr_ethernet_hdr *eth_head;
	uint16_t ether_type;
	struct sr_arphdr *arp_header;
	int ret;

	iface = sr_get_interface(sr, interface);
	printf("\ninterface: %s\n", interface);
	printf("len: %d\n", len);
	new_packet = malloc(len);
	check_malloc_error(new_packet);
	eth_head = (struct sr_ethernet_hdr *)new_packet;
	ether_type = htons(ETHERTYPE_ARP);
	// set reply type to ETHERTYPE_ARP
	memcpy(&eth_head->ether_shost, &iface->addr, ETHER_ADDR_LEN);
	memcpy(eth_head->ether_dhost, &send_to_all, ETHER_ADDR_LEN);
	memcpy(&eth_head->ether_type, &ether_type, sizeof(uint16_t));
	arp_header = (struct sr_arphdr *)(new_packet + sizeof(struct sr_ethernet_hdr));
	// standard values
	arp_header->ar_hrd = htons(ARPHDR_ETHER);
	arp_header->ar_pro = htons(ETHERTYPE_IP);
	arp_header->ar_hln = ETHER_ADDR_LEN;
	arp_header->ar_pln = sizeof(uint32_t);
	arp_header->ar_op = htons(ARP_REQUEST);
	memcpy(&arp_header->ar_sha, &iface->addr, ETHER_ADDR_LEN);
	arp_header->ar_sip = iface->ip;
	printf("\niface ip=%u\n", iface->ip);
	memset(&arp_header->ar_tha, 0, ETHER_ADDR_LEN);
	// 0 means we do not know target MAC address yet
	arp_header->ar_tip = target_ip;
	printf("\nnext hop ip=%u\n", target_ip);
	DebugMAC(arp_header->ar_tha);
	ret = sr_send_packet(sr, new_packet, len, interface);
	if (new_packet)
		free(new_packet);
	printf("\nretval of arp packet sent: %d\n", ret);
}
/*---------------------------------------------------------------------
 * Method:my_own_iface
 *check if the packet is for one of the routers own interfaces
 *---------------------------------------------------------------------*/
int my_own_iface(struct sr_instance *sr, uint32_t D)
{
	struct sr_if *iface = sr->if_list;

	while (iface != NULL)
	{
		if (iface->ip == D)
		{
			return 1;
		}
		iface = iface->next;
	}

	return 0;
}
/*---------------------------------------------------------------------
 * Method: find_dest_entry_rt
 * find the apropriate routing table entry given a dest ip
 *---------------------------------------------------------------------*/
struct sr_rt *find_dest_entry_rt(struct sr_instance *sr, uint32_t D)
{
	uint32_t max_prefix;
	struct sr_rt *entry;
	struct sr_rt *rt_walker;
	uint32_t calc1;
	uint32_t calc2;
	if (!sr->active)
		return NULL;
	struct in_addr addr;
	addr.s_addr = D;
	printf("Dest IP lookup in rt: %s\n", inet_ntoa(addr));

	max_prefix = 0;
	rt_walker = sr->routing_table;
	while (rt_walker)
	{
		calc1 = D & rt_walker->mask.s_addr;
		calc2 = rt_walker->dest.s_addr & rt_walker->mask.s_addr;
		addr.s_addr = calc2;

		printf("*** -> D prefix %s \n", inet_ntoa(addr));

		if (calc1 == calc2)
		{
			printf("*** -> match in rt %s \n", inet_ntoa(rt_walker->gw));
			if (D==rt_walker->dest.s_addr)
			return (rt_walker);
			if (rt_walker->mask.s_addr >= max_prefix)
			{
				max_prefix = rt_walker->mask.s_addr;
				entry = rt_walker;
			}
		}
		rt_walker = rt_walker->next;
	}
	return (entry);
}
/*---------------------------------------------------------------------
 * Method: find_cache_entry
 * find the apropriate routing table entry given a dest ip
 *---------------------------------------------------------------------*/
unsigned char *find_cache_entry(struct sr_instance *sr, uint32_t ip)
{
	struct sr_cache_arp *cache_walker;
	unsigned char *addr;

	cache_walker = sr->cache;
	addr = NULL;
	while (cache_walker)
	{
		if (ip == cache_walker->ip)
		{
			struct sr_rt *entry_in_rt = find_dest_entry_rt(sr,
														   cache_walker->ip);
			uint32_t time_new = (uint32_t)time(NULL);
			if ((time_new - cache_walker->time) > 10)
			{
				make_and_send_arp_request(sr, cache_walker->ip,
										  arp_header_len, entry_in_rt->interface);
				printf("cache timed out for ip: %d\n new cache req sent", cache_walker->ip);
				return NULL;
			}
			addr = cache_walker->addr;
			break;
		}
		cache_walker = cache_walker->next;
	}
	return (addr);
}

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr)
{
	/* REQUIRES */
	assert(sr);

	/* Add initialization code here! */
	sr->cache = NULL;
	sr->buffer = NULL;
	sr->main_neighbor = NULL;
	sr->side_neighbor = NULL;
	sr->active = 0;

	if (sr->routing_table == 0)
	{
		printf("\nSecondary router selected\n");
		sr->main_router = 0;
		sr->active = 0;
		// add_if_to_rt(sr);
	}
	else
	{
		printf("\nMain router selected\n");

		sr->main_router = 1;
	}

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance *sr, uint8_t *packet /* lent */,
					 unsigned int len, char *interface /* lent */)
{
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);

	printf("*** -> Received packet of length %d \n", len);
	struct sr_if *iface = sr_get_interface(sr, interface);

	struct sr_ethernet_hdr *eth_head = (struct sr_ethernet_hdr *)packet;
	uint16_t ether_type = ntohs(eth_head->ether_type);

	if (ether_type == ETHERTYPE_ARP)
	{
		struct sr_arphdr *arp_req = (struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr));

		uint16_t arp_op = ntohs(arp_req->ar_op);
		printf("*** -> ARP packet op-code: %u \n", arp_op);
		printf("*** -> ARP packet target ip address: %u \n", arp_req->ar_tip);

		if (arp_op == 1) // signifying arp request
		{
			if (!(iface->ip == arp_req->ar_tip))
			{ // no ip match
				printf("*** -> No Ip match with the router %u \n",
					   arp_req->ar_tip);
				return;
			}

			uint8_t *reply = malloc(len);
			check_malloc_error(reply);

			uint16_t reply_type = htons(ETHERTYPE_ARP);
			memcpy(reply, packet, len);
			struct sr_ethernet_hdr *eth_head_reply = (struct sr_ethernet_hdr *)reply;
			struct sr_arphdr *arp_req_reply = (struct sr_arphdr *)(reply + sizeof(struct sr_ethernet_hdr));
			unsigned short arp_op_reply = htons(ARP_REPLY); // reply op code = 2
			memcpy(&eth_head_reply->ether_shost, &iface->addr, ETHER_ADDR_LEN);
			// sender's ether mac to router's mac
			memcpy(&eth_head_reply->ether_dhost, &arp_req->ar_sha,
				   ETHER_ADDR_LEN);
			// set reply type to ETHERTYPE_ARP
			eth_head_reply->ether_type = reply_type;
			// reciever's ether mac to send mac
			arp_req_reply->ar_op = arp_op_reply;
			// sender's mac to target mac
			memcpy(&arp_req_reply->ar_tha, &arp_req->ar_sha, ETHER_ADDR_LEN);
			// sender's ip to target ip
			arp_req_reply->ar_tip = arp_req->ar_sip;
			// receiver's ip to sender ip
			arp_req_reply->ar_sip = arp_req->ar_tip;
			// receiver's mac to sender mac
			memcpy(&arp_req_reply->ar_sha, &iface->addr, ETHER_ADDR_LEN);

			sr_send_packet(sr, reply, len, interface);
			if (reply)
				free(reply);
		}
		else if (arp_op == 2) // ARP reply
		{
			printf("*** -> Got ARP op-code for reply: %u and ip: %u \n", arp_op,
				   arp_req->ar_sip);

			if (sr->cache == NULL)
			{ // adding to the cache
				sr->cache = malloc(sizeof(struct sr_cache_arp));
				check_malloc_error(sr->cache);
				sr->cache->ip = arp_req->ar_sip;
				memcpy(&sr->cache->addr, &arp_req->ar_sha,
					   ETHER_ADDR_LEN);
				sr->cache->time = (uint32_t)time(NULL);
				sr->cache->next = NULL;
				printf("*** -> cache ip: %u \n", sr->cache->ip);

				printf("Seconds of the packet: %d\n", sr->cache->time);
			}
			else
			{
				struct sr_cache_arp *cache_walker = sr->cache;
				while (1)
				{
					if (cache_walker->ip == arp_req->ar_sip)

					{ // adding to the cache

						printf("updating cache ip of new arp packet: %u\n",
							   arp_req->ar_sip);
						memcpy(&cache_walker->addr, &arp_req->ar_sha,
							   ETHER_ADDR_LEN);
						cache_walker->time = (uint32_t)time(NULL);
						printf("Seconds of the packet: %d\n",
							   sr->cache->time);
						break;
					}
					else if (cache_walker->next == NULL)
					{ // adding to the cache
						cache_walker->next = malloc(sizeof(struct sr_cache_arp));
						check_malloc_error(cache_walker->next);
						cache_walker->next->ip = arp_req->ar_sip;
						memcpy(&cache_walker->next->addr,
							   &arp_req->ar_sha, ETHER_ADDR_LEN);
						cache_walker->next->time = (uint32_t)time(NULL);
						cache_walker->next->next = NULL;
						printf("Seconds of the packet: %d\n",
							   cache_walker->next->time);
						break;
					}
					cache_walker = cache_walker->next;
				}
			}
			// code to send packets from the buffer
			struct buffer_ip_packet *buff_walker = sr->buffer;
			struct buffer_ip_packet *buff_walker_prev = sr->buffer;
			if (buff_walker)
			{
				struct sr_cache_arp *cache_walker = sr->cache;
				int packet_sent = 0;
				while (buff_walker)
				{
					if (packet_sent)
						break;
					cache_walker = sr->cache;
					while (cache_walker)
					{
						printf("cache ip:%u buffer ip:%u\n", cache_walker->ip,
							   buff_walker->ip);

						if (buff_walker->ip == cache_walker->ip)
						{
							struct sr_ethernet_hdr *eth_head_packet_buffer = (struct sr_ethernet_hdr *)(buff_walker->packet);
							struct sr_rt *entry_in_rt = find_dest_entry_rt(sr,
																		   buff_walker->ip);

							struct sr_if *new_interface_iface = sr_get_interface(sr,
																				 entry_in_rt->interface);
							printf("interface %s\n", entry_in_rt->interface);
							memcpy(&eth_head_packet_buffer->ether_shost,
								   &new_interface_iface->addr, ETHER_ADDR_LEN);
							memcpy(&eth_head_packet_buffer->ether_dhost,
								   &cache_walker->addr, ETHER_ADDR_LEN);
							make_and_send_ip_request(sr, buff_walker->packet, buff_walker->len,
													 entry_in_rt->interface);
							printf("buffered packet with next hop ip:%u sent\n", buff_walker->ip);
							if (buff_walker == sr->buffer)
							{
								printf("First buff value sent\n");
								sr->buffer = buff_walker->next;
							}

							else if (buff_walker->next)
							{
								buff_walker_prev->next = buff_walker->next;
							}
							else
							{
								buff_walker_prev->next = NULL;
							}
							packet_sent = 1;
							break;
						}
						cache_walker = cache_walker->next;
					}
					buff_walker_prev = buff_walker;
					buff_walker = buff_walker->next;
				}
			}
		}
	}
	else if (ether_type == ETHERTYPE_IP)
	{
		printf("*** -> PACKET with IP Request %u \n", ether_type);
		struct ip *ip_packet = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));

		struct in_addr dest_addr = ip_packet->ip_dst;
		uint32_t dest_ip_address = dest_addr.s_addr;
		if (my_own_iface(sr, dest_ip_address))
		{
			// ICMP handling stuff
			struct ip *ip_packet = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));

			if (ip_packet->ip_p == IPPROTO_ICMP)
			{
				// get the ICMP part from IP packet
				uint8_t *icmp_part = packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip);
				if (*icmp_part == 8)
				{ //  echo Request = 8
					uint8_t *reply = malloc(len);
					check_malloc_error(reply);
					struct sr_ethernet_hdr *eth_head_reply = (struct sr_ethernet_hdr *)reply;

					memcpy(eth_head_reply->ether_shost, eth_head->ether_dhost, ETHER_ADDR_LEN);
					memcpy(eth_head_reply->ether_dhost, eth_head->ether_shost, ETHER_ADDR_LEN);

					struct in_addr src_ip = ip_packet->ip_src;
					struct ip *ip_header_rep = (struct ip *)(packet + sizeof(struct sr_ethernet_hdr));

					ip_header_rep->ip_v = 4;
					ip_header_rep->ip_hl = 5;
					ip_header_rep->ip_tos = ip_packet->ip_tos;
					ip_header_rep->ip_len = htons(len - sizeof(struct sr_ethernet_hdr));
					ip_header_rep->ip_src = ip_packet->ip_dst;
					ip_header_rep->ip_dst = src_ip;
					ip_header_rep->ip_id = htons(ip_packet->ip_id);
					ip_header_rep->ip_off = 0;
					ip_header_rep->ip_ttl = 64;
					ip_header_rep->ip_p = ip_packet->ip_p;
					ip_header_rep->ip_sum = 0;
					ip_header_rep->ip_sum = cksum(reply + sizeof(struct sr_ethernet_hdr),
												  sizeof(struct ip)); // checksum changed
					*icmp_part = 0;									  //  echo Reply = 0
					uint16_t *icmp_checksum = (uint16_t *)(icmp_part + 2);
					*icmp_checksum = 0;
					*icmp_checksum = cksum(icmp_part, len - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip));
					memcpy(reply + sizeof(struct sr_ethernet_hdr), packet + sizeof(struct sr_ethernet_hdr), len - sizeof(struct sr_ethernet_hdr));
					make_and_send_ip_request(sr, reply, len, interface);
					printf("echo back sent\n");
				}
			}
		}

		else if (ip_packet->ip_p == PROTOCOL_OSPF)
		{

			struct ospfv2_hdr *ospf_header = (struct ospfv2_hdr *)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));

			printf("ospf message detected\n");

			if (ospf_header->type == OSPF_TYPE_HELLO)
			{

				add_neighbor(sr, packet, interface);
				printf("hello message detected\n");
				struct in_addr rid;
				rid.s_addr = ospf_header->rid;
				printf("router IP: %s\n", inet_ntoa(rid));
			}

			if (ospf_header->type == OSPF_TYPE_LSU)
			{
				add_lsu_to_rt(sr, packet, interface);
				printf("lsu update  detected\n");

			}
		}
		else
		{
			printf("sender IP: %s\n", inet_ntoa(ip_packet->ip_src));
			printf("dest IP: %s\n", inet_ntoa(ip_packet->ip_dst));
			uint16_t reply_type_ip = htons(ETHERTYPE_IP);
			eth_head->ether_type = reply_type_ip;
			ip_packet->ip_ttl--;
			if (ip_packet->ip_ttl == 0)
				return; // as specified in spec
			printf("*** -> time to live %u \n", ip_packet->ip_ttl);
			printf("*** -> ip len %u \n", ip_packet->ip_len);
			ip_packet->ip_sum = 0;
			ip_packet->ip_sum = cksum(packet + sizeof(struct sr_ethernet_hdr),
									  sizeof(struct ip));						 // checksum changed
			struct sr_rt *entry_in_rt = find_dest_entry_rt(sr, dest_ip_address); // routing table entry for dest ip D
			if (!entry_in_rt)
			{
				printf("\n Packet discarded cuz no entry found in rt.\n");
				return;
			}
			uint32_t next_hop_ip = entry_in_rt->gw.s_addr == 0 ? dest_ip_address : entry_in_rt->gw.s_addr; // next hop ip
			printf("*** -> next hop ip %u \n", next_hop_ip);
			printf("*** -> next hop ip in routing table %u \n", entry_in_rt->gw.s_addr);
			struct in_addr next_hop_ip_printed;
			next_hop_ip_printed.s_addr = next_hop_ip;
			printf("*** -> next hop ip in correct form %s \n", inet_ntoa(next_hop_ip_printed));

			unsigned char *mac_addr = find_cache_entry(sr, next_hop_ip);

			if (mac_addr)
			{
				printf("\nmatch found in cache with ip: %u\n", next_hop_ip);
				struct sr_if *new_interface_iface = sr_get_interface(sr,
																	 entry_in_rt->interface);
				memcpy(&eth_head->ether_shost, &new_interface_iface->addr,
					   ETHER_ADDR_LEN);
				memcpy(&eth_head->ether_dhost, mac_addr, ETHER_ADDR_LEN);
				make_and_send_ip_request(sr, packet, len,
										 entry_in_rt->interface);
			}
			else
			{
				printf("\nno match found in cache with ip: %u\n", next_hop_ip);
				add_to_buff(sr, packet, len, next_hop_ip);
				make_and_send_arp_request(sr, next_hop_ip,
										  arp_header_len, entry_in_rt->interface);
			}
		}
	}
}
