/*-----------------------------------------------------------------------------
 * file:  sr_rt.c
 * date:  Mon Oct 07 04:02:12 PDT 2002
 * Author:  casado@stanford.edu
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#define __USE_MISC 1 /* force linux to show inet_aton */
#include <arpa/inet.h>

#include "sr_rt.h"
#include "sr_router.h"

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

int sr_load_rt(struct sr_instance *sr, const char *filename)
{
    FILE *fp;
    char line[BUFSIZ];
    char dest[32];
    char gw[32];
    char mask[32];
    char iface[32];
    uint16_t cost = 1; // initial costs are assumed to be one
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;

    /* -- REQUIRES -- */
    assert(filename);
    if (access(filename, R_OK) != 0)
    {
        perror("access");
        return -1;
    }

    fp = fopen(filename, "r");

    while (fgets(line, BUFSIZ, fp) != 0)
    {
        if (EOF == sscanf(line, "%s %s %s %s", dest, gw, mask, iface))
            break;
        if (inet_aton(dest, &dest_addr) == 0)
        {
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    dest);
            return -1;
        }
        if (inet_aton(gw, &gw_addr) == 0)
        {
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    gw);
            return -1;
        }
        if (inet_aton(mask, &mask_addr) == 0)
        {
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    mask);
            return -1;
        }
        sr_add_rt_entry(sr, dest_addr, gw_addr, mask_addr, iface, cost);
    } /* -- while -- */

    return 0; /* -- success -- */
} /* -- sr_load_rt -- */

void sr_add_rt_entry(struct sr_instance *sr, struct in_addr dest,
                     struct in_addr gw, struct in_addr mask, char *if_name, uint16_t cost)
{
    struct sr_rt *rt_walker = sr->routing_table;

    /* -- REQUIRES -- */
    assert(if_name);
    assert(sr);

    /* -- Check if routing table is empty -- */
    if (rt_walker == NULL)
    {
        /* Routing table is empty, add a new entry */
        rt_walker = (struct sr_rt *)malloc(sizeof(struct sr_rt));
        assert(rt_walker);
        rt_walker->next = NULL;
        rt_walker->dest = dest;
        rt_walker->gw = gw;
        rt_walker->mask = mask;
        rt_walker->cost = cost;
        strncpy(rt_walker->interface, if_name, SR_IFACE_NAMELEN);
        sr->routing_table = rt_walker;

        return;
    }

    /* -- Check if entry already exists -- */
    while (rt_walker)
    {
        if (rt_walker->dest.s_addr == dest.s_addr)
        {
            if (rt_walker->cost >= cost) //>= operator means add the latest best cost
            {
                rt_walker->gw = gw;
                rt_walker->mask = mask;
                rt_walker->cost = cost;
                strncpy(rt_walker->interface, if_name, SR_IFACE_NAMELEN);
                return;
            }
            else
            { 
                return; // if cost is already good, no need to update
            }
        }

        rt_walker = rt_walker->next;
    }

    /* -- Entry does not exist, add a new one -- */
    rt_walker = (struct sr_rt *)malloc(sizeof(struct sr_rt));
    assert(rt_walker);

    rt_walker->next = sr->routing_table;
    sr->routing_table = rt_walker;

    rt_walker->dest = dest;
    rt_walker->gw = gw;
    rt_walker->mask = mask;
    rt_walker->cost = cost;
    strncpy(rt_walker->interface, if_name, SR_IFACE_NAMELEN);
}

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_remove_rt_entries(struct sr_instance *sr, uint32_t gw)
{
    struct sr_rt *current = sr->routing_table;
    struct sr_rt *prev = NULL;

    /* Iterate through the routing table */
    while (current != NULL)
    {
        if (current->gw.s_addr == gw)
        {
            if (prev == NULL)
            {
                sr->routing_table = current->next;
            }
            else
            {
                prev->next = current->next;
            }

            free(current);
            current = current->next;
        }
        else
        {
            prev = current;
            current = current->next;
        }
    }
}

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_change_rt_entries(struct sr_instance *sr, uint32_t old_gw, uint32_t new_gw, char *iface)
{
    struct sr_rt *current = sr->routing_table;

    /* Iterate through the routing table */
    while (current != NULL)
    {
        if (current->gw.s_addr == old_gw)
        {
            current->gw.s_addr = new_gw;
            memcpy(current->interface, iface, 4);
        }
        current = current->next;
    }
}

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_table(struct sr_instance *sr)
{
    struct sr_rt *rt_walker = 0;

    if (sr->routing_table == 0)
    {
        printf(" *warning* Routing table empty \n");
        return;
    }

    printf("Destination\t  Gateway\t\tMask\tIface\tCost\n");

    rt_walker = sr->routing_table;

    sr_print_routing_entry(rt_walker);
    while (rt_walker->next)
    {
        rt_walker = rt_walker->next;
        sr_print_routing_entry(rt_walker);
    }

} /* -- sr_print_routing_table -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_entry(struct sr_rt *entry)
{
    /* -- REQUIRES --*/
    assert(entry);
    assert(entry->interface);

    printf("%s\t", inet_ntoa(entry->dest));
    printf("%s\t", inet_ntoa(entry->gw));
    printf("%s\t", inet_ntoa(entry->mask));
    printf("%s\t", entry->interface);
    printf("%d\n", entry->cost);

} /* -- sr_print_routing_entry -- */
