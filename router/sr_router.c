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

  /* fill in code here */

  /* Need to check if packet is (1) IP packet or (2) ARP reply/request */

  /* Print ethernet header */
  print_hdr_eth(packet);

  uint16_t ethtype = ethertype(packet);   /* Determine Ethernet type */

  if (ethtype == ethertype_ip) {
    printf(">>> IP Packet Received:\n");
    print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));     /* Print IP header */
    /* TODO: handle IP packets */
  }
  
  else if (ethtype == ethertype_arp) {
    printf(">>> ARP Packet Received:\n");
    /* Print ARP header */
    print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));

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
  }

} /* end sr_ForwardPacket */
