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

  printf("*** -> RECEIVED PACKET OF LENGTH %d <- ***\n", len);

  /* CODE HERE */
  /* Packet Length check */
  if (len < sizeof(struct sr_ethernet_hdr)) {
    fprintf(stderr, ">>> ERROR: sr_handlepacket() Packet too short.\n");
    return;
  }

  /* Determine Ethernet type */
  /* print_hdr_eth(packet); */
  uint16_t ethtype = ethertype(packet);

  /* 1. IF PACKET IS IP PACKET */
  if (ethtype == ethertype_ip) {          
    printf(">>> IP Packet Received:\n");

    /* 1a. IP Packet Length Check */
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
      fprintf(stderr, ">>> ERROR: sr_handlepacket() IP packet too short.\n");
      return;
    }
    /* print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t)); */

    /* 1b. Cast the IP header */
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    /* An incoming IP packet may be destined for 
    (i) one of your router’s IP addresses, (ii) or it may be destined elsewhere. */

    /* 1c. Check if IP packet is destined for the router - find matching interface */
    struct sr_if *iface_entry = sr->if_list;
    while(iface_entry != NULL) {
      if (iface_entry->ip == ip_header->ip_dst) {
        /* Case 1: If packet is meant for our router's IP addresses */
        printf(">>> IP packet is meant for this router. Handling...\n");
        handle_ip_packet(sr, packet, len, iface_entry); 
        return;
      }
      iface_entry = iface_entry->next;
    }
    /* Case 2: If packet is destined elsewhere, forward it */
    struct sr_if *source_interface = sr_get_interface(sr, interface);
    printf(">>> IP packet is meant for another router, forwarding.\n");
    forward_ip_packet(sr, packet, len, source_interface);
  }
  
  /* 2. IF PACKET IS ARP PACKET */
  else if (ethtype == ethertype_arp) {                    
    printf(">>> ARP Packet Received:\n");              
    
    /* 2a. ARP Packet Length Check */
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
      fprintf(stderr, ">>> ERROR: sr_handlepacket() ARP packet too short.\n");
      return;
    }
    /* print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t)); */

    /* 2b. Cast the ARP header */
    sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    uint16_t arp_op = ntohs(arp_header->ar_op);

    /* Check if ARP reply OR ARP request and handle if target IP address is one of the router's IP addresses */
    /* 2c. If ARP Request  */
    if (arp_op == arp_op_request) {
      printf(">>> ARP Packet is an ARP request. Handling...\n");
      struct sr_if *iface_entry = sr->if_list;
      while(iface_entry != NULL) {
        /* Look for the matching interface from list of interfaces */
        if (iface_entry->ip == arp_header->ar_tip) {
          handle_arp_request(sr, packet, iface_entry);
          return;
        }
        iface_entry = iface_entry->next;
      }
    } 
    /* 2d. If ARP Reply */
    else if (arp_op == arp_op_reply) {
      printf(">>> ARP Packet is an ARP reply. Handling...\n");
      struct sr_if *iface_entry = sr->if_list;
      while(iface_entry != NULL) {
      /* Look for the matching interface from list of interfaces */
      if (iface_entry->ip == arp_header->ar_tip) {
        handle_arp_reply(sr, packet, iface_entry);
        return;
      }
      iface_entry = iface_entry->next;
    }
  }
  return;
  }

  /* 3. If packet not IP nor ARP, ignore */
  else {
    printf(">>> INFO: sr_handlepacket() Packet of unknown ethertype received: 0x%04x\n", ethtype);
    return;
  }

} /* end sr_handlepacket */


void handle_icmp_messages(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *outgoing_interface, uint8_t icmp_type, uint8_t icmp_code) {
  /* The source address of an ICMP message can be the source address 
  of any of the incoming interfaces, as specified in RFC 792. 
  The only incoming ICMP message destined towards the router’s IPs 
  that you have to explicitly process are ICMP echo requests */

  /* 1. Determine total length of new ICMP packet to allocate space for it */
  unsigned int icmp_len;
  /* Echo Reply uses the original packet length */
  if (icmp_type == 0) {
    icmp_len = len;
  } else {
    icmp_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  }

  /* 2. Allocate space for ICMP packet */
  uint8_t *icmp_packet = malloc(icmp_len);
  memset(icmp_packet, 0, icmp_len);

  /* 3. Build the Ethernet header */
  sr_ethernet_hdr_t *original_ethernet_header = (sr_ethernet_hdr_t *)packet;
  sr_ethernet_hdr_t *new_ethernet_header = (sr_ethernet_hdr_t *)icmp_packet;
  /* Swap source and destination MAC addresses since we are sending it back */
  memcpy(new_ethernet_header->ether_dhost, original_ethernet_header->ether_shost, ETHER_ADDR_LEN);
  memcpy(new_ethernet_header->ether_shost, outgoing_interface->addr, ETHER_ADDR_LEN);
  /* Set ethertype to IP */
  new_ethernet_header->ether_type = htons(ethertype_ip);

  /* 4. Build the IP header */
  sr_ip_hdr_t *original_ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_ip_hdr_t *new_ip_header = (sr_ip_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t));

  /* Some values are taken from: https://www.ietf.org/rfc/rfc792.txt */
  new_ip_header->ip_v = 4;
  new_ip_header->ip_hl = 5;
  new_ip_header->ip_ttl = 64;
  new_ip_header->ip_p = ip_protocol_icmp;
  new_ip_header->ip_off = htons(IP_DF);
  new_ip_header->ip_tos = 0;
  new_ip_header->ip_src = outgoing_interface->ip;     /* IP packet coming from router */
  new_ip_header->ip_dst = original_ip_header->ip_src; /* back to the original sender */

  /* 4. Set IP total length */
  if (icmp_type == 0 && icmp_code == 0) {
    /* Echo Reply uses the original packet length */
    new_ip_header->ip_len = original_ip_header->ip_len;
  } else {
    new_ip_header->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  }

  /* 5. Compute checksum */
  new_ip_header->ip_sum = 0;
  new_ip_header->ip_sum = cksum(new_ip_header, sizeof(sr_ip_hdr_t));

  /* 6. Build ICMP header - but this depends on ICMP type */
  sr_icmp_hdr_t *original_icmp_header = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /* For ECHO REPLY */
  if (icmp_type == 0 && icmp_code == 0) {
    sr_icmp_hdr_t *new_icmp_header = (sr_icmp_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    unsigned int original_icmp_length = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
    memcpy(new_icmp_header, original_icmp_header, original_icmp_length);
    new_icmp_header->icmp_type = 0;       /* Type 0 */
    new_icmp_header->icmp_code = 0;       /* Code 0 */
    new_icmp_header->icmp_sum = 0;        /* Checksum */
    new_icmp_header->icmp_sum = cksum(new_icmp_header, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
  }

  /* For ERROR MESSAGES */
  else {
  sr_icmp_t3_hdr_t *new_icmp_header = (sr_icmp_t3_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  new_icmp_header->icmp_type = icmp_type;
  new_icmp_header->icmp_code = icmp_code;
  new_icmp_header->unused = 0;
  new_icmp_header->next_mtu = 0;
  /* Copy original IP header + first 8 bytes of data */
  memcpy(new_icmp_header->data, packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t) + 8);
  new_icmp_header->icmp_sum = 0;
  new_icmp_header->icmp_sum = cksum(new_icmp_header, sizeof(sr_icmp_t3_hdr_t));
  }

  /* 7. Send the new ICMP packet */
  sr_send_packet(sr, icmp_packet, icmp_len, outgoing_interface->name);
  free(icmp_packet);
}


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
  ip_header->ip_sum = received_sum;
  if (received_sum != computed_sum) {
    fprintf(stderr, "ERROR: handle_ip_packet() Invalid checksum.\n");
    return;
  }

  /* Check if packet is ICMP echo request */
  if (ip_header->ip_p == ip_protocol_icmp) {
    printf(">>> IP packet is ICMP packet.\n");
    /* ICMP Packet Length Check */
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)) {
      fprintf(stderr, ">>> ERROR: handle_ip_packet() ICMP packet too short.\n");
      return;
    }
    /* Cast the ICMP Header */
    sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* ICMP Echo Request = ICMP type 8 - from https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages */
    /* If ICMP echo request, send echo reply */
    if (icmp_header->icmp_type == 8) {
      printf(">>> ICMP ERROR MESSAGE: ECHO REQUEST. \n");
      handle_icmp_messages(sr, packet, len, matching_interface, 0, 0);
      return;
    }
    /* Ignore other types of ICMP messages for now */
    return;
  }
  /* If the packet contains a TCP or UDP payload, send an ICMP port unreachable to the sending host. */
  else if (ip_header->ip_p == 6 || ip_header->ip_p == 17) {
    printf(">>> ICMP ERROR MESSAGE: PORT UNREACHABLE (TCP/UDP PAYLOAD RECEIVED).\n");
    handle_icmp_messages(sr, packet, len, matching_interface, 3, 3);
    return;
  }
  /* Otherwise, ignore the packet */
}


void forward_ip_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *source_interface) {
  /* FOR IP PACKETS DESTINED ELSEWHERE */
  /* If an error occurs in any of the steps, you will have to send an ICMP message 
  back to the sender notifying them of an error. 
  You may also get an ARP request or reply, which has to interact with the ARP cache correctly. */

  /* Sanity-check the packet (meets minimum length and has correct checksum). 
  If a packet is malformed, the router should silently drop it. */
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) { 
    fprintf(stderr, ">>> ERROR: forward_ip_packet() Packet too short.\n");
    return;
  }

  /* Cast the IP header */
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* Verify IP checksum */
  uint16_t received_sum = ip_header->ip_sum;
  ip_header->ip_sum = 0;
  if (received_sum != cksum(ip_header, sizeof(sr_ip_hdr_t))) {
    fprintf(stderr, ">>> ERROR: forward_ip_packet() Invalid checksum.\n");
    ip_header->ip_sum = received_sum;
    return;
  }
  /* Restore before we modify IP fields */
  ip_header->ip_sum = received_sum;

  /* Decrement the TTL by 1 */
  ip_header->ip_ttl--;
  if (ip_header->ip_ttl == 0) {
    /* If TTL = 0, send ICMP message back to the source interface/sender that it came from */
    printf(">>> ICMP ERROR MESSAGE: TTL IS ZERO.\n");
    handle_icmp_messages(sr, packet, len, source_interface, 11, 0);
  }

  /* Recompute the packet checksum over the modified header */
  ip_header->ip_sum = 0;
  ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

  /* Find out which entry in the routing table has the longest prefix match with the destination IP address. */
  struct sr_rt *routing_table_entry = sr->routing_table;
  struct sr_rt *best_match_entry = NULL;
  uint32_t best_mask = 0;
  uint32_t destination_ip_host = ntohl(ip_header->ip_dst);

  /* Perform longest prefix match */
  while(routing_table_entry != NULL) {
    printf(">>> Performing Longest Prefix Match...\n");
    uint32_t entry_dest = ntohl(routing_table_entry->dest.s_addr);
    uint32_t entry_mask = ntohl(routing_table_entry->mask.s_addr);
    
    /* If prefix matches prefix of entry, then we check if it's the longest prefix match too */
    if ((destination_ip_host & entry_mask) == (entry_dest & entry_mask)) {
      if (entry_mask > best_mask) {
        best_mask = entry_mask;
        best_match_entry = routing_table_entry;
      }
    }
    routing_table_entry = routing_table_entry->next;
  }

  /* If no LPM found, send ICMP message Destination net unreachable - a non-existent route to the destination IP  */
  if (!best_match_entry) {
    fprintf(stderr, ">>> ERROR: forward_ip_packet() No matching prefix found.\n");
    printf(">>> ICMP ERROR: DESTINATION NET UNREACHABLE. NO LPM FOUND.\n");
    handle_icmp_messages(sr, packet, len, source_interface, 3, 0);
    return;
  }
  
  /* If LPM found, check the ARP cache for the next-hop MAC address corresponding to the next-hop IP. */
  /* uint32_t next_hop_ip = best_match_entry->gw.s_addr; */
  uint32_t next_hop_ip;
  /* If the destination host is directly reachable on this interface, send it to the frame's MAC address */
  if (best_match_entry->gw.s_addr == 0) {
      next_hop_ip = ip_header->ip_dst; 
  } 
  /* Else, send it to the gateway address */
  else {
      next_hop_ip = best_match_entry->gw.s_addr; 
  }
  
  /* If it’s there, send it. */
  struct sr_arpentry *its_there = sr_arpcache_lookup(&sr->cache, next_hop_ip);
  if (its_there) {
    printf(">>> Found next-hop address in ARP Cache. Preparing to send packet...\n");
    /* Update source and destination information before sending the packet */
    sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)packet;
    struct sr_if *outgoing_interface = sr_get_interface(sr, best_match_entry->interface);
    /* Update source information */
    memcpy(ethernet_header->ether_shost, outgoing_interface->addr, ETHER_ADDR_LEN);
    /* Update destination information */
    memcpy(ethernet_header->ether_dhost, its_there->mac, ETHER_ADDR_LEN);
    /* Send the packet to the next hop MAC address corresponding to the next hop IP */
    printf(">>> Sending IP Packet to LPM address...\n");
    sr_send_packet(sr, packet, len, best_match_entry->interface);
    free(its_there);
    return;
  }

  /* Otherwise, send an ARP request for the next-hop IP (if one hasn’t been sent within the last second), 
  and add the packet to the queue of packets waiting on this ARP request. */
  else {
    printf(">>> Sending ARP request for next-hop address. Adding packet to queue of packets waiting on ARP request...\n");
    struct sr_arpreq *arp_request = sr_arpcache_queuereq(&sr->cache, next_hop_ip, packet, len, best_match_entry->interface);
    handle_arpreq(sr, arp_request);
  }
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
  printf(">>> Received ARP Request. Sending ARP reply... \n");
  sr_send_packet(sr, arp_reply_packet, arp_reply_len, matching_interface->name);
  free(arp_reply_packet);
}


void handle_arp_reply(struct sr_instance *sr, uint8_t *packet, struct sr_if *matching_interface) {
  /* Cast the ARP header */
  sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  
  /* Insert this IP to MAC mapping in the cache, and get its request queue */
  printf(">>> ARP reply received. Retrieving request queue...\n");
  struct sr_arpreq *arp_req = sr_arpcache_insert(&sr->cache, arp_header->ar_sha, arp_header->ar_sip);   
  if (arp_req == NULL) {
    return;
  }
  else {
    printf(">>> Request queue retrieved. Handling packets in request queue...\n");
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
  printf(">>> Queued packets sent. ARP request removed from queue.\n");
  sr_arpreq_destroy(&sr->cache, arp_req);
  }
}