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
    fprintf(stderr, "** Error: packet is wayy to short \n");
    return -1;
  }

  uint8_t *copy = malloc(len);          /* Make copy of packet */
  if (!copy) {
      fprintf(stderr, "MALLOC ERROR in sr_handlepacket\n");
      return;
  }
  memcpy(copy, packet, len);

  print_hdr_eth(copy);                    /* Print Ethernet header */
  uint16_t ethtype = ethertype(copy);     /* Determine Ethernet type */

  if (ethtype == ethertype_ip) {          /* If packet is IP packet */
    printf(">>> IP Packet Received:\n");
    print_hdr_ip(copy + sizeof(sr_ethernet_hdr_t));
    handle_ip_packet();

  }
  
  else if (ethtype == ethertype_arp) {                               /* If packet is ARP reply/request */
    printf(">>> ARP Packet Received:\n");
    print_hdr_arp(copy + sizeof(sr_ethernet_hdr_t));                 /* Print ARP header */
    
    sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));  /* Cast arp header */

    /* Check if ARP reply OR ARP request and handle if target IP address is one of the router's IP addresses */
    if (arp_header->ar_op == arp_op_request) {
      struct sr_if *iface_entry = sr->if_list;
      while(iface_entry != NULL) {
        /* Look for the matching interface from list of interfaces */
        if (iface_entry->ip == arp_header->ar_tip) {
          handle_arp_request(sr, copy, iface_entry);
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
        handle_arp_reply(sr, copy, iface_entry);
        return;
      }
      iface_entry = iface_entry->next;
    }
  }
  }
  free(copy);
} /* end sr_ForwardPacket */


void handle_arp_request(struct sr_instance *sr, uint8_t *packet, struct sr_if *matching_interface) {
  /* Cast the ARP header */
  sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  
  /* Repackage the request as an ARP reply */
  unsigned int arp_reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *arp_reply_packet = malloc(arp_reply_len);
  if (!arp_reply_packet) {
      fprintf(stderr, "MALLOC ERROR in handle_arp_request\n");
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
                      
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet);     /* Cast ARP header to retrieve destination IP address */
  struct sr_arpentry *sr_arpcache_lookup;
  sr_arpcache_lookup = arpcache_lookup(sr->cache, arp_hdr);   /* Look up MAC address of IP address */
  if (sr_arpcache_lookup) { /* if MAC address exists */
    sr_send_packet(sr, packet, len, interface); /* send packet */
    free(sr_arpcache_lookup);  /* free the arp entry */
  }
  else {
    struct sr_arpreq *sr_arpcache_queuereq = sr_arpcache_queureq(&sr->cache, arp_hdr->ar_tip, packet, len, interface); /* if no MAC address found in cache, put it in queue */
    handle_arpreq(sr, sr_arpcache_queuereq);
  }
} /* end sr_ForwardPacket */
