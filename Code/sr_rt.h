/*-----------------------------------------------------------------------------
 * file:  sr_rt.h 
 * date:  Mon Oct 07 03:53:53 PDT 2002  
 * Author: casado@stanford.edu
 *
 * Description:
 *
 * Methods and datastructures for handeling the routing table
 *
 *---------------------------------------------------------------------------*/

#ifndef sr_RT_H
#define sr_RT_H

#ifdef _DARWIN_
#include <sys/types.h>
#endif

#include <netinet/in.h>

#include "sr_if.h"

/* ----------------------------------------------------------------------------
 * struct sr_rt
 *
 * Node in the routing table 
 *
 * -------------------------------------------------------------------------- */

struct sr_rt
{
    struct in_addr dest;
    struct in_addr gw;
    struct in_addr mask;
    char   interface[SR_IFACE_NAMELEN];
    uint16_t cost;
    struct sr_rt* next;
};


int sr_load_rt(struct sr_instance*,const char*);
void sr_add_rt_entry(struct sr_instance* sr, struct in_addr dest,
                     struct in_addr gw, struct in_addr mask, char* if_name,uint16_t cost);
void sr_change_rt_entries(struct sr_instance* sr, uint32_t old_gw, uint32_t new_gw,char* iface);
void sr_remove_rt_entries(struct sr_instance* sr, uint32_t gw);

void sr_print_routing_table(struct sr_instance* sr);
void sr_print_routing_entry(struct sr_rt* entry);


#endif  /* --  sr_RT_H -- */
