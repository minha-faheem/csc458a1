#include "sr_router.h"

#include <assert.h>
#include <stdio.h>

#include "sr_arpcache.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr) {
  /* REQUIRES */
  assert(sr);

  /* Initialize cache and cache cleanup thread */
  sr_arpcache_init(&(sr->cache));

  pthread_attr_init(&(sr->attr));
  pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_t thread;

  pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

  /* Add initialization code here! */

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
                     unsigned int len, char *interface /* lent */) {
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  /* CODE HERE */
  /* Need to check if packet is (1) IP packet or (2) ARP reply/request, and handle accordingly. */


  uint8_t *copy = malloc(len);            /* Make copy of packet */
  memcpy(copy, packet, len);

  print_hdr_eth(copy);                    /* Print Ethernet header */
  uint16_t ethtype = ethertype(copy);   /* Determine Ethernet type */

  if (ethtype == ethertype_ip) {          /* If packet is IP packet */
    printf(">>> IP Packet Received:\n");
    print_hdr_ip(copy + sizeof(sr_ethernet_hdr_t));

    /* Is the packet destined to this router? Aka me? Is the destination IP the same as my IP?
    If so, ICMP echo request. TCP/UDP */


    /* 1. Sanity-check the packet (meets minimum length and has correct checksum). 
    If a packet is malformed, the router should silently drop it. */
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(copy + sizeof(sr_ethernet_hdr_t)); /* Cast ip header to retrieve destination IP address */
    uint16_t ip_header_length = ip_header->ip_hl * 4; /* Calculate IP header length */
    if (len < sizeof(sr_ethernet_hdr_t) + ip_header_length) {
      free(copy);
      return;
    }
    uint16_t checksum = ip_header->ip_sum; /* Store original checksum */
    ip_header->ip_sum = 0;                 /* Set checksum to 0 for calculation */
    if (cksum(ip_header, ip_header_length) != checksum) {
      free(copy);
      return; /* Drop packet */
    }
    ip_header->ip_sum = checksum;          /* Restore original checksum */

    /* 2. Decrement the TTL by 1, and recompute the packet checksum over the modified header. */
    ip_header->ip_ttl -= 1;

    /* 3. Find out which entry in the routing table has the longest prefix match with the destination IP address. */ 
    struct sr_rt *routing_table = sr->routing_table; /* Get routing table */
    struct sr_rt *longest_match = NULL;               /* Initialize longest match */
    uint32_t dest_ip = ip_header->ip_dst;             /* Get destination IP address */
    while (routing_table != NULL) {
      if ((dest_ip & routing_table->mask.s_addr) == (routing_table->dest.s_addr & routing_table->mask.s_addr)) {
        if (longest_match == NULL || ntohl(routing_table->mask.s_addr) > ntohl(longest_match->mask.s_addr)) {
          longest_match = routing_table; /* Update longest match */
        }
      }
      routing_table = routing_table->next; /* Move to next entry */
    }

    /* 4. Check the ARP cache for the next-hop MAC address corresponding to the next-hop IP.
    If it’s there, send it. Otherwise, send an ARP request for the next-hop IP (if one hasn’t
    been sent within the last second), and add the packet to the queue of packets waiting on
    this ARP request.*/








  }
  
  else if (ethtype == ethertype_arp) {                                /* If packet is ARP reply/request */
    printf(">>> ARP Packet Received:\n");
    print_hdr_arp(copy + sizeof(sr_ethernet_hdr_t));                 /* Print ARP header */
    
    sr_arp_hdr_t *arp_header = (struct sr_arp_hdr_t *)(copy);        /* Cast arp header */

    /* Check if ARP reply/request */
    if (arp_header->ar_op == arp_op_request) {
      struct sr_if *interface = sr->if_list;
      while (interface != NULL) {
          if (interface->ip == arp_header->ar_tip) {                          /* Compare target IP with the router's interface IPs */
            /* Since a match is found, send it over as an ARP reply */
            arp_header->ar_op = arp_op_reply;                                 /* Repackage packet as ARP Reply */
            sr_send_packet(sr, (uint8_t *)arp_header, len, interface->name);  /* Send packet */
            break;                                                            /* Exit the loop if a match is found */
          }
          interface = interface->next;
      }

    } else if (arp_header->ar_op == arp_op_reply) {
      struct sr_if *interface = sr_get_interface(sr, interface);              /* Get the interface instance */
      struct sr_arpreq *req = sr_arpcache_insert(sr->cache, interface->addr, arp_header->ar_tip);   /* Inserts this IP to MAC mapping in the cache, if found */
      if (req == NULL) {
        free(copy);
        return;
      }
      struct sr_packet *req_packet = req->packets;                          /* Get the list of packets waiting on this ARP request */
      while (req_packet != NULL) {
        struct sr_packet *next_req_packet = req_packet->next;               /* Store next packet before sending current packet */
        sr_send_packet(sr, req_packet, req_packet->len, req_packet->iface); /* Send the packet */
        req_packet = next_req_packet;                                       /* Move to the next packet */
      }
  }
  free(copy);
} /* end sr_ForwardPacket */




void sr_ForwardPacket(struct sr_instance *sr, uint8_t *packet /* lent */,
                     unsigned int len, char *interface /* lent */){
                      
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet);     /* Cast ARP header to retrieve destination IP address */
  struct sr_arpentry *sr_arpcache_lookup = arpcache_lookup(sr->cache, arp_hdr);   /* Look up MAC address of IP address */
  if (sr_arpcache_lookup) { /* if MAC address exists */
    sr_send_packet(sr, packet, len, interface); /* send packet */
    free(sr_arpcache_lookup);  /* free the arp entry */
  }
  else {
    struct sr_arpreq *sr_arpcache_queuereq = sr_arpcache_queureq(&sr->cache, arp_hdr->ar_tip, packet, len, interface); /* if no MAC address found in cache, put it in queue */
    handle_arpreq(sr, sr_arpcache_queuereq);
  }
} /* end sr_ForwardPacket */
