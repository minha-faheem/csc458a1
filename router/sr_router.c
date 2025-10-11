#include "sr_router.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

  /* Don't waste my time ... */
  if (len < sizeof(struct sr_ethernet_hdr)) {
    fprintf(stderr, ">>> ERROR: sr_handlepacket() Packet too short.\n");
    return;
  }

  uint8_t *packet_copy = malloc(len);            /* Make copy of packet to use in helper functions */
  if (!packet_copy) {
      fprintf(stderr, ">>> ERROR: sr_handlepacket() malloc error when making packet copy.\n");
      return;
  }
  memcpy(packet_copy, packet, len);

  print_hdr_eth(packet);                    /* Print Ethernet header */
  uint16_t ethtype = ethertype(packet);     /* Determine Ethernet type */

  if (ethtype == ethertype_ip) {          /* If packet is IP packet */
    printf(">>> IP Packet Received:\n");
    print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));

    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    /* An incoming IP packet may be destined for (1) one of your router’s IP addresses, 
    (2) or it may be destined elsewhere. 
    
    If it is sent to one of your router’s IP addresses, you should take the following actions */
    /* IF Router is meant for our Router's IP addresses, then check: */
    /* 1. If the packet is an ICMP echo request and its checksum is valid, send an ICMP echo reply to the sending host.*/
    /* Create a function, handle_icmp_echo request() */
    /* 2. If the packet contains a TCP or UDP payload, send an ICMP port unreachable to the sending host.*/
    /* Create a function, handle_icmp_echo_request() */
    /* 3. Otherwise, ignore the packet */

    /* ELSE if packet is destined elsewhere, */
    /* 4. But, packets destined elsewhere should be forwarded using normal fowarding logic */
    /* Create a function, forward_ip_packet() */

    struct sr_if *iface_entry = sr->if_list;
    while(iface_entry != NULL) {
      /* Look for the matching interface from list of interfaces */
      if (iface_entry->ip == ip_header->ip_dst) {
        /* Case 1: If packet is meant for our router's IP addresses */
        handle_ip_packet(sr, packet_copy, len, iface_entry); 
        return;
      }
      iface_entry = iface_entry->next;
    }
    /* Case 2: If packet is destined elsewhere */
    forward_ip_packet(sr, packet_copy, len);
  }
  
  else if (ethtype == ethertype_arp) {                               /* If packet is ARP reply/request */
    printf(">>> ARP Packet Received:\n");
    print_hdr_arp(packet_copy + sizeof(sr_ethernet_hdr_t));                 /* Print ARP header */
    
    sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));  /* Cast arp header */

    /* Check if ARP reply OR ARP request and handle if target IP address is one of the router's IP addresses */
    if (arp_header->ar_op == arp_op_request) {
      struct sr_if *iface_entry = sr->if_list;
      while(iface_entry != NULL) {
        /* Look for the matching interface from list of interfaces */
        if (iface_entry->ip == arp_header->ar_tip) {
          handle_arp_request(sr, packet_copy, iface_entry);
          return;
        }
        iface_entry = iface_entry->next;
      }
    } 
    else if (arp_header->ar_op == arp_op_reply) {
      struct sr_if *iface_entry = sr->if_list;
      while(iface_entry != NULL) {
      /* Look for the matching interface from list of interfaces */
      if (iface_entry->ip == arp_header->ar_tip) {
        handle_arp_reply(sr, packet_copy, iface_entry);
        return;
      }
      iface_entry = iface_entry->next;
    }
  }
  }
  free(packet_copy);
} /* end sr_ForwardPacket */


void handle_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *matching_interface) {
  /* FOR IP PACKETS DESTINED TO OUR ROUTER */
  
  /* Cast the header */
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  
  /* If the packet is an ICMP echo request and its checksum is valid, 
  send an ICMP echo reply to the sending host. */

  /* Verify checksum is valid */
  uint16_t received_sum = ip_header->ip_sum;
  ip_header->ip_sum = 0;
  uint16_t computed_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
  ip_header->ip_sum = received_sum;     /* TODO: Do I set the checksum back? */
  if (received_sum != computed_sum) {
    fprintf(stderr, "ERROR: handle_ip_packet() Invalid checksum. \n");
    return;
  }

  /* Check if packet is ICMP echo request */
  if (ip_header->ip_p == ip_protocol_icmp) {
    /* Cast the ICMP Header */
    sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* TODO: How do I know which one is ICMP echo request and TCP/UDP message? */
    if (icmp_header->icmp_type == 8) {
      /* If echo request, send along */
      handle_icmp_messages();
    }

  /* If the packet contains a TCP or UDP payload, send an ICMP port unreachable to the sending host. */
  else {
    handle_icmp_messages();
  }
  /* Otherwise, ignore the packet */
}

void forward_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len) {
  /* FOR IP PACKETS DESTINED ELSEWHERE */

  /* If an error occurs in any of the steps, you will have to send an ICMP
  message back to the sender notifying them of an error. You may also get an ARP request or
  reply, which has to interact with the ARP cache correctly. */

  /* Cast the IP header*/
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* Sanity-check the packet (meets minimum length and has correct checksum). 
  If a packet is malformed, the router should silently drop it. */
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) { 
    fprintf(stderr, ">>> ERROR: forward_ip_packet() Packet too short.\n");
    return;
  }

  /* Decrement the TTL by 1 */
  ip_header->ip_ttl--;
  if (ip_header->ip_ttl == 0) {
    /* If TTL = 0, send ICMP message time exceeded }*/
    handle_icmp_messages();
  }
  /* Recompute the packet checksum over the modified header */
  ip_header->ip_sum = 0;
  ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

  /* Find out which entry in the routing table has the longest prefix match with the destination IP address. */
  struct sr_rt *rt_entry = sr->routing_table;
  struct sr_rt *best_match_entry = NULL;
  uint32_t best_mask = 0;

  while(rt_entry != NULL) {
    /* Perform longest prefix match */
    uint32_t dest_ip = ntohl(ip_header->ip_dst);
    uint32_t entry_dest = ntohl(rt_entry->dest.s_addr);
    uint32_t entry_mask = ntohl(rt_entry->mask.s_addr);
    
    /* If prefix matches prefix of entry, then we check if it's the longest prefix match too */
    if ((dest_ip & entry_mask) == (entry_dest & entry_mask)) {
      if (entry_mask > best_mask) {
        best_mask = entry_mask;
        best_match_entry = rt_entry;
      }
    }
    rt_entry = rt_entry->next;
  }

  /* If no LPM found, send ICMP message */
  if (!best_match_entry) {
    fprintf(stderr, ">>> ERROR: forward_ip_packet() No matching prefix found.\n");
    handle_icmp_messages();
    return;
  }

  /* TODO: can I use sr_Forwardpacket here, after updating source and destination in ethernet header? */
  
  /* If LPM found, 
  Check the ARP cache for the next-hop MAC address corresponding to the next-hop IP.
  If it’s there, send it. */
  uint32_t next_hop_ip = best_match_entry->gw.s_addr;
  struct sr_arpentry *its_there = sr_arpcache_lookup(&sr->cache, next_hop_ip);
  if (its_there) {
    /* Update source and destination information before sending the packet */
    sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)packet;
    /* Update source information */
    struct sr_if *outgoing_interface = sr_get_interface(sr, best_match_entry->interface);
    memcpy(ethernet_header->ether_shost, outgoing_interface->addr, ETHER_ADDR_LEN);
    /* Update destination information */
    memcpy(ethernet_header->ether_dhost, its_there->mac, ETHER_ADDR_LEN);
    sr_send_packet(sr, packet, len, best_match_entry->interface);
    free(its_there);
  }

  /* Otherwise, send an ARP request for the next-hop IP (if one hasn’t been sent within the last second), 
  and add the packet to the queue of packets waiting on this ARP request. */
  else {
    struct sr_arpreq *arp_request = sr_arpcache_queuereq(&sr->cache, next_hop_ip, packet, len, best_match_entry->interface);
    handle_arpreq(arp_request, sr);
  }
}

void handle_icmp_messages() {
  return;
}


void handle_arp_request(struct sr_instance *sr, uint8_t *packet, struct sr_if *matching_interface) {
  /* Cast the ARP header */
  sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  
  /* Repackage the request as an ARP reply */
  unsigned int arp_reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *arp_reply_packet = malloc(arp_reply_len);
  if (!arp_reply_packet) {
      fprintf(stderr, ">>> ERROR: handle_arp_request() malloc error when creating ARP reply.\n");
      return;
  }

  /* Repackage the Ethernet and ARP headers */
  sr_ethernet_hdr_t *arp_reply_ethernet_header = (sr_ethernet_hdr_t *)arp_reply_packet;
  sr_arp_hdr_t *arp_reply_header = (sr_arp_hdr_t *)(arp_reply_packet + sizeof(sr_ethernet_hdr_t));

  /* Set Ethernet header fields - set source MAC address from original arp request into destination MAC address of arp reply */
  memcpy(arp_reply_ethernet_header->ether_dhost, ((sr_ethernet_hdr_t *)packet)->ether_shost, ETHER_ADDR_LEN);
  memcpy(arp_reply_ethernet_header->ether_shost, matching_interface->addr, ETHER_ADDR_LEN);
  arp_reply_ethernet_header->ether_type = htons(ethertype_arp);

  /* Set ARP header fields - repackage as an ARP reply and set source's MAC and IP addresses to be interface's MAC and IP address  */
  arp_reply_header->ar_hrd = arp_header->ar_hrd;
  arp_reply_header->ar_pro = arp_header->ar_pro;
  arp_reply_header->ar_hln = arp_header->ar_hln;
  arp_reply_header->ar_pln = arp_header->ar_pln;
  arp_reply_header->ar_op = htons(arp_op_reply);
  memcpy(arp_reply_header->ar_sha, matching_interface->addr, ETHER_ADDR_LEN);
  arp_reply_header->ar_sip = matching_interface->ip;
  memcpy(arp_reply_header->ar_tha, arp_header->ar_sha, ETHER_ADDR_LEN);
  arp_reply_header->ar_tip = arp_header->ar_sip;

  /* Send the ARP reply forward */
  sr_send_packet(sr, arp_reply_packet, arp_reply_len, matching_interface->name);
  /* free(arp_reply_packet); */
}

void handle_arp_reply(struct sr_instance *sr, uint8_t *packet, struct sr_if *matching_interface) {
  /* Cast the ARP header */
  sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  
  /* Insert this IP to MAC mapping in the cache, and get its request queue */
  struct sr_arpreq *arp_req = sr_arpcache_insert(&sr->cache, arp_header->ar_sha, arp_header->ar_sip);   
  if (arp_req == NULL) {
    free(packet);
    return;
  }
  else {
    /* If there are requests waiting on this packet, send them */
    struct sr_packet *queued_packet = arp_req->packets;
    while(queued_packet != NULL) {
      /* Update Ethernet header with correct MAC addresses - set destination MAC to the one just learned */ 
      sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)queued_packet->buf;
      memcpy(eth_hdr->ether_dhost, arp_header->ar_sha, ETHER_ADDR_LEN);

      /* Set source MAC to outgoing interface */
      struct sr_if *outgoing_iface = sr_get_interface(sr, queued_packet->iface);
      if (outgoing_iface) {
        memcpy(eth_hdr->ether_shost, outgoing_iface->addr, ETHER_ADDR_LEN);
      }

      /* Send the packet forward */
      sr_send_packet(sr, queued_packet->buf, queued_packet->len, queued_packet->iface);
      queued_packet = queued_packet->next;
    }
  /* Once queued packets sent, remove the ARP request from the queue */
  sr_arpreq_destroy(&sr->cache, arp_req);
  }
  /* free(packet); */
}



void sr_ForwardPacket(struct sr_instance *sr, uint8_t *packet /* lent */,
                     unsigned int len, char *interface /* lent */){
                      
  sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *)(packet);     /* Cast ARP header to retrieve destination IP address */
  /* sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)); */
  struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, arp_header); /* Look up MAC address of IP address */
  if (sr_arpcache_lookup) { /* if MAC address exists */
    sr_send_packet(sr, packet, len, interface); /* send packet */
    free(sr_arpcache_lookup);  /* free the arp entry */
  }
  else {
    struct sr_arpreq *sr_arpcache_queuereq = sr_arpcache_queureq(&sr->cache, arp_header->ar_tip, packet, len, interface); /* if no MAC address found in cache, put it in queue */
    handle_arpreq(sr, sr_arpcache_queuereq);
  }
} /* end sr_ForwardPacket */
