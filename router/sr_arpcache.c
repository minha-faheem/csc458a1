#include "sr_arpcache.h"

#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_router.h"

/*
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.

  You will need to add ARP requests and packets waiting on responses to those ARP requests
  to the ARP request queue. 
  When an ARP response arrives, you will have to remove the ARP request from the queue 
    and place it onto the ARP cache, forwarding any packets that were
    waiting on that ARP request. 
  
  Pseudocode for these operations is provided in sr arpcache.h.
  The base code already creates a thread that times out ARP cache entries 15 seconds after they
  are added for you. You must fill out the sr arpcache sweepreqs function in sr arpcache.c
  that gets called every second to iterate through the ARP request queue and re-send ARP
  requests if necessary. Pseudocode for this is provided in sr arpcache.h.

*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
  /* Fill this in */ 
  struct sr_arpreq *req = sr->cache.requests;
  struct sr_arpreq *next_req = NULL;

  while(req != NULL){
    next_req = req->next; /* save the next pointer before calling handle_arpreq */
    handle_arpreq(sr, req);
    req = next_req;
  }
}


void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *sr_arpreq) {
  /* Get current time */ 
  time_t current_time;
  time(&current_time);

  /* Calculate time difference since the last ARP request was sent */
  double diff_t;
  diff_t = difftime(current_time, sr_arpreq->sent);

  /* Check if it has been more than 1 second since last ARP request */
  if (diff_t > 1.0) {
    /* If 5 ARP requests already sent, send icmp host unreachable to source addr of all pkts waiting on this request */
    if (sr_arpreq->times_sent >= 5) {
      struct sr_packet *queued_packet = sr_arpreq->packets;
      while(queued_packet) {
        struct sr_if *outgoing_interface = sr_get_interface(sr, queued_packet->iface);
        if (outgoing_interface) {
          printf(">>> ICMP ERROR MESSAGE: DESTINATION HOST UNREACHABLE.\n");
          handle_icmp_messages(sr, queued_packet->buf, queued_packet->len, outgoing_interface, 3, 1);
        }
        queued_packet = queued_packet->next;
      }
      sr_arpreq_destroy(&sr->cache, sr_arpreq);       /* Destroy ARP request */
    }
    else {
      /* If less than ARP requests sent, resend the ARP request */
      struct sr_if *outgoing_interface = sr_get_interface(sr, sr_arpreq->packets->iface);
      if (!outgoing_interface) {
        fprintf(stderr, ">>> ERROR: handle_arpreq() No interface found for ARP resend.\n");
        return;
      }
      
      /* If interface found, construct the ARP request */
      /* Send ARP request - similar to handle_arp_request() in sr_router.c */
      unsigned int arp_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
      uint8_t *arp_packet = malloc(arp_packet_len);
      if (!arp_packet) {
          fprintf(stderr, ">>> ERROR: handle_arpreq() malloc error when creating ARP reply.\n");
          return;
      }

      /* Construct Ethernet header*/
      sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t *)arp_packet;
      /* Broadcast this MAC address */
      memset(ethernet_header->ether_dhost, 0xFF, ETHER_ADDR_LEN);
      /* Set source MAC to the outgoing interface MAC */
      memcpy(ethernet_header->ether_shost, outgoing_interface->addr, ETHER_ADDR_LEN);
      /* Set ethernet type for ARP */
      ethernet_header->ether_type = htons(ethertype_arp);
      
      /* Construct ARP header */
      sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *)(arp_packet + sizeof(sr_ethernet_hdr_t));
      arp_header->ar_hrd = htons(arp_hrd_ethernet);
      arp_header->ar_pro = htons(ethertype_ip);
      arp_header->ar_hln = ETHER_ADDR_LEN;
      arp_header->ar_pln = sizeof(uint32_t);
      arp_header->ar_op  = htons(arp_op_request);
      memcpy(arp_header->ar_sha, outgoing_interface->addr, ETHER_ADDR_LEN);
      arp_header->ar_sip = outgoing_interface->ip;
      memset(arp_header->ar_tha, 0x00, ETHER_ADDR_LEN);   /* Don't know target MAC address yet */
      arp_header->ar_tip = sr_arpreq->ip;

      /* Send the packet forward to interface */
      sr_send_packet(sr, arp_packet, arp_packet_len, outgoing_interface->name);
      free(arp_packet);

      /* Update times sent */
      sr_arpreq->sent = current_time;
      sr_arpreq->times_sent++;
    }
  }
}



/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
  pthread_mutex_lock(&(cache->lock));

  struct sr_arpentry *entry = NULL, *copy = NULL;

  int i;
  for (i = 0; i < SR_ARPCACHE_SZ; i++) {
    if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
      entry = &(cache->entries[i]);
    }
  }

  /* Must return a copy b/c another thread could jump in and modify
     table after we return. */
  if (entry) {
    copy = (struct sr_arpentry *)malloc(sizeof(struct sr_arpentry));
    memcpy(copy, entry, sizeof(struct sr_arpentry));
  }

  pthread_mutex_unlock(&(cache->lock));

  return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.

   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache, uint32_t ip,
                                       uint8_t *packet, /* borrowed */
                                       unsigned int packet_len, char *iface) {
  pthread_mutex_lock(&(cache->lock));

  struct sr_arpreq *req;
  for (req = cache->requests; req != NULL; req = req->next) {
    if (req->ip == ip) {
      break;
    }
  }

  /* If the IP wasn't found, add it */
  if (!req) {
    req = (struct sr_arpreq *)calloc(1, sizeof(struct sr_arpreq));
    req->ip = ip;
    req->next = cache->requests;
    cache->requests = req;
  }

  /* Add the packet to the list of packets for this request */
  if (packet && packet_len && iface) {
    struct sr_packet *new_pkt =
        (struct sr_packet *)malloc(sizeof(struct sr_packet));

    new_pkt->buf = (uint8_t *)malloc(packet_len);
    memcpy(new_pkt->buf, packet, packet_len);
    new_pkt->len = packet_len;
    new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
    strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
    new_pkt->next = req->packets;
    req->packets = new_pkt;
  }

  pthread_mutex_unlock(&(cache->lock));

  return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac, uint32_t ip) {
  pthread_mutex_lock(&(cache->lock));

  struct sr_arpreq *req, *prev = NULL, *next = NULL;
  for (req = cache->requests; req != NULL; req = req->next) {
    if (req->ip == ip) {
      if (prev) {
        next = req->next;
        prev->next = next;
      } else {
        next = req->next;
        cache->requests = next;
      }

      break;
    }
    prev = req;
  }

  int i;
  for (i = 0; i < SR_ARPCACHE_SZ; i++) {
    if (!(cache->entries[i].valid))
      break;
  }

  if (i != SR_ARPCACHE_SZ) {
    memcpy(cache->entries[i].mac, mac, 6);
    cache->entries[i].ip = ip;
    cache->entries[i].added = time(NULL);
    cache->entries[i].valid = 1;
  }

  pthread_mutex_unlock(&(cache->lock));

  return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
  pthread_mutex_lock(&(cache->lock));

  if (entry) {
    struct sr_arpreq *req, *prev = NULL, *next = NULL;
    for (req = cache->requests; req != NULL; req = req->next) {
      if (req == entry) {
        if (prev) {
          next = req->next;
          prev->next = next;
        } else {
          next = req->next;
          cache->requests = next;
        }

        break;
      }
      prev = req;
    }

    struct sr_packet *pkt, *nxt;

    for (pkt = entry->packets; pkt; pkt = nxt) {
      nxt = pkt->next;
      if (pkt->buf)
        free(pkt->buf);
      if (pkt->iface)
        free(pkt->iface);
      free(pkt);
    }

    free(entry);
  }

  pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
  fprintf(stderr,
          "\nMAC            IP         ADDED                      VALID\n");
  fprintf(stderr,
          "-----------------------------------------------------------\n");

  int i;
  for (i = 0; i < SR_ARPCACHE_SZ; i++) {
    struct sr_arpentry *cur = &(cache->entries[i]);
    unsigned char *mac = cur->mac;
    fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0],
            mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip),
            ctime(&(cur->added)), cur->valid);
  }

  fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {
  /* Seed RNG to kick out a random entry if all entries full. */
  srand(time(NULL));

  /* Invalidate all entries */
  memset(cache->entries, 0, sizeof(cache->entries));
  cache->requests = NULL;

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(cache->attr));
  pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(cache->lock), &(cache->attr));

  return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
  return pthread_mutex_destroy(&(cache->lock)) &&
         pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were
   added more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
  struct sr_instance *sr = sr_ptr;
  struct sr_arpcache *cache = &(sr->cache);

  while (1) {
    sleep(1.0);

    pthread_mutex_lock(&(cache->lock));

    time_t curtime = time(NULL);

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
      if ((cache->entries[i].valid) &&
          (difftime(curtime, cache->entries[i].added) > SR_ARPCACHE_TO)) {
        cache->entries[i].valid = 0;
      }
    }

    sr_arpcache_sweepreqs(sr);

    pthread_mutex_unlock(&(cache->lock));
  }

  return NULL;
}
