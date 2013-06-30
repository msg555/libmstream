#include "daemon.h"
#include "stream.h"

#include <mstream.h>

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

static const size_t HEADER_SIZE = 12;

struct rdatagram {
  size_t len;
  size_t read_pos;
  char buf[1];
};

#define PARAM_LENGTH(param) ((param) >> 2)
#define PARAM_HAS_ACK1(param) (((param) & 0x1) != 0)
#define PARAM_HAS_ACK2(param) (((param) & 0x2) != 0)
#define PARAM_CREATE(length, has_ack1, has_ack2) ((uint16_t) \
      (((length) << 2) | ((has_ack1) ? 0x1 : 0x0) | ((has_ack2) ? 0x2 : 0x0)))

static int datagram_compare_tx_order(void* px, void* py) {
  return (int)(((struct datagram*)px)->tx_index -
               ((struct datagram*)py)->tx_index) < 0;
}

static size_t datagram_get_tx_id(void *x) {
  return ((struct datagram*)x)->tx_heap_id;
}

static void datagram_set_tx_id(void *x, size_t id) {
  ((struct datagram*)x)->tx_heap_id = id;
}

static int datagram_compare_rtx_time(void* px, void* py) {
  return (int64_t)(((struct datagram*)px)->rtx_time -
                   ((struct datagram*)py)->rtx_time) < 0;
}

static size_t datagram_get_rtx_id(void *x) {
  return ((struct datagram*)x)->rtx_heap_id;
}

static void datagram_set_rtx_id(void *x, size_t id) {
  ((struct datagram*)x)->rtx_heap_id = id;
}

static struct light_stream* lstream_create(struct mstream* stream,
                                           uint32_t id) {
  struct light_stream* lstream = (struct light_stream*)
        calloc(1, sizeof(struct light_stream));
  lstream->parent = stream;
  lstream->id = id;
  pthread_cond_init(&lstream->cond, NULL);

  _mstream_heap_init(&lstream->tx_heap, datagram_compare_tx_order,
                     datagram_get_tx_id, datagram_set_tx_id);
  _mstream_heap_init(&lstream->rtx_heap, datagram_compare_rtx_time,
                     datagram_get_rtx_id, datagram_set_rtx_id);
  return lstream;
}

static void lstream_destroy(struct light_stream* lstream) {
  pthread_cond_destroy(&lstream->cond);

  _mstream_heap_destroy(&lstream->tx_heap);
  _mstream_heap_destroy(&lstream->rtx_heap);
  free(lstream);
}

static void recompute_times(struct light_stream* lstream, time_val now) {
  struct mstream* parent = lstream->parent;

  if(lstream->tx_time == 0) {
    if((lstream->tx_buf_size &&
        !lstream->out_packets[lstream->tx_seq_num & (MAX_PACKETS - 1)]) ||
        lstream->tx_heap.size) {
      /* Schedule a packet write. */
      parent->tx_last = lstream->tx_time = max_time(now,
          parent->tx_last + _mstream_congestion_spacing(&parent->cinfo));
    } else if(lstream->ack_size) {
      /* Schedule a pure ACK. */
      lstream->tx_time = max_time(now,
          parent->tx_last + _mstream_congestion_spacing(&parent->cinfo));
    }
  } else if(!((lstream->tx_buf_size &&
              !lstream->out_packets[lstream->tx_seq_num & (MAX_PACKETS - 1)]) ||
              lstream->tx_heap.size || lstream->ack_size)) {
    lstream->tx_time = 0;
  }

  uint64_t rtx_time = !lstream->rtx_heap.size ? 0 :
        ((struct datagram*)_mstream_heap_top(&lstream->rtx_heap))->rtx_time;

  time_val ntime = lstream->tx_time;
  if(ntime && rtx_time) {
    ntime = min_time(ntime, rtx_time);
  } else if(rtx_time) {
    ntime = rtx_time;
  }

  if(ntime != lstream->time) {
    pthread_mutex_lock(&parent->daemon->lock);
    if(ntime) {
      int need_add = lstream->time == 0;
      lstream->time = ntime;

      if(need_add) {
        _mstream_heap_add(&parent->daemon->stream_heap, lstream);
      } else {
        _mstream_heap_adjust(&parent->daemon->stream_heap, lstream);
      }
    } else {
      lstream->time = 0;
      _mstream_heap_remove(&parent->daemon->stream_heap, lstream);
    }
    _mstream_daemon_adjust_timer(parent->daemon);
    pthread_mutex_unlock(&parent->daemon->lock);
  }
}

static size_t lstream_write(struct light_stream* lstream, const void* buf,
                            size_t len, int flags) {
  size_t amt;
  const char* cbuf = (const char*)buf;
  struct mstream* parent = lstream->parent;

  pthread_mutex_lock(&parent->lock);

  while(lstream->tx_buf_size == TX_BUFFER_SIZE) {
    pthread_cond_wait(&lstream->cond, &parent->lock);
  }

  amt = min_sz(len, TX_BUFFER_SIZE - lstream->tx_buf_size);
  while(amt) {
    size_t pos = (lstream->tx_buf_pos + lstream->tx_buf_size) &
                    (TX_BUFFER_SIZE - 1);
    size_t wamt = min_sz(amt, TX_BUFFER_SIZE - pos);
    memcpy(lstream->tx_buf + pos, cbuf, wamt);
    cbuf += wamt;
    amt -= wamt;
    lstream->tx_buf_size += wamt;
  }

  recompute_times(lstream, get_time());
  pthread_mutex_unlock(&parent->lock);

  return cbuf - (const char*)buf;
}

static void ack_packet(struct light_stream* lstream, uint16_t pkt_id) {
  struct mstream* parent = lstream->parent;
  if(lstream->ack_size == MAX_PACKETS) {
    /* ACKs like pakcets can be dropped on best effort.  If an ACK is lost
     * the remote will retransmit and another ACK will be generated. */
    return;
  }

  lstream->ack_list[(lstream->ack_pos + lstream->ack_size++) &
                    (MAX_PACKETS - 1)] = pkt_id;
  recompute_times(lstream, get_time());
}

static size_t lstream_read(struct light_stream* lstream, void* buf, size_t len,
                           int flags, int* ready) {
  char* cbuf = (char*)buf;
  struct mstream* parent = lstream->parent;

  pthread_mutex_lock(&parent->lock);

  /* Wait for data if requested. */
  if(~flags & MSG_DONTWAIT) {
    while(!lstream->packets[lstream->packet_pos & (MAX_PACKETS - 1)]) {
      pthread_cond_wait(&lstream->cond, &parent->lock);
    }
  }

  while(len && lstream->packets[lstream->packet_pos & (MAX_PACKETS - 1)]) {
    struct rdatagram* dg = lstream->packets[lstream->packet_pos &
                                            (MAX_PACKETS - 1)];
    size_t amt = min_sz(len, dg->len - dg->read_pos);

    memcpy(cbuf, dg->buf + dg->read_pos, amt);
    cbuf += amt;
    dg->read_pos += amt;
    len -= amt;

    /* If we finished reading the packet free it, ack it, and move to the next
     * packet. */
    if(dg->read_pos == dg->len) {
      free(dg);
      lstream->packets[lstream->packet_pos & (MAX_PACKETS - 1)] = NULL;
      lstream->packet_pos++;
    }
  }

  pthread_mutex_unlock(&parent->lock);
  return cbuf - (char*)buf;
}

static void lstream_flush(struct light_stream* lstream) {
  pthread_mutex_lock(&lstream->parent->lock);
  while(lstream->time) {
    pthread_cond_wait(&lstream->cond, &lstream->parent->lock);
  }
  pthread_mutex_unlock(&lstream->parent->lock);
}

static struct light_stream* stream_get_locked(struct mstream* stream,
                                              uint32_t id) {
  while(stream->streams_size <= id) {
    size_t old_size = stream->streams_size;
    stream->streams_size = old_size * 3 / 2 + 4;
    stream->streams = (struct light_stream**)realloc(stream->streams,
        stream->streams_size * sizeof(struct light_stream));
    memset(stream->streams + old_size, 0, (stream->streams_size - old_size) *
                                          sizeof(struct light_stream));
  }
  if(!stream->streams[id]) {
    stream->streams[id] = lstream_create(stream, id);
  }

  return stream->streams[id];
}

static struct light_stream* stream_get(struct mstream* stream, uint32_t id) {
  struct light_stream* ret;
  pthread_mutex_lock(&stream->lock);
  ret = stream_get_locked(stream, id);
  pthread_mutex_unlock(&stream->lock);
  return ret;
}

static void stream_list_push_locked(struct mstream* stream,
                                    struct light_stream* lstream) {
  lstream->next = NULL;
  if(stream->ready_head) {
    stream->ready_tail->next = lstream;
    stream->ready_tail = lstream;
  } else {
    stream->ready_head = stream->ready_tail = lstream;
    pthread_cond_signal(&stream->cond);
  }
}

static void stream_list_pop_locked(struct mstream* stream) {
  struct light_stream* head = stream->ready_head;
  if(head->next) {
    head->next = stream->ready_head = stream->ready_tail = NULL;
  } else {
    stream->ready_head = head->next;
    head->next = NULL;
  }
}

static uint16_t pop_ack(struct light_stream* lstream) {
  uint16_t ret = 0;
  if(lstream->ack_size) {
    ret = lstream->ack_list[lstream->ack_pos];
    lstream->ack_size--;
    lstream->ack_pos = (lstream->ack_pos + 1) & (MAX_PACKETS - 1);
  }
  return ret;
}

static struct datagram* datagram_create(struct light_stream* lstream,
                                        size_t len) {
  assert(HEADER_SIZE <= len);
  assert(!lstream->out_packets[lstream->tx_seq_num & (MAX_PACKETS - 1)]);

  struct datagram* dg = (struct datagram*)malloc(
                            offsetof(struct datagram, buf) + len);
  dg->len = len;
  dg->tx_index = lstream->tx_seq_num++;
  dg->tx_heap_id = dg->rtx_heap_id = 0;

  lstream->out_packets[dg->tx_index & (MAX_PACKETS - 1)] = dg;
  *(uint32_t*)dg->buf = htonl(lstream->id);
  ((uint16_t*)dg->buf)[2] = htons(dg->tx_index);
  ((uint16_t*)dg->buf)[3] = htons(PARAM_CREATE(len - HEADER_SIZE,
      lstream->ack_size >= 1, lstream->ack_size >= 2));
  ((uint16_t*)dg->buf)[4] = htons(pop_ack(lstream));
  ((uint16_t*)dg->buf)[5] = htons(pop_ack(lstream));
  return dg;
}

static void transmit_packet(struct light_stream* lstream, uint64_t now) {
  struct datagram* dg = NULL;
  struct mstream* parent = lstream->parent;
  if(lstream->tx_buf_size && lstream->tx_heap.size == 0 &&
     !lstream->out_packets[lstream->tx_seq_num & (MAX_PACKETS - 1)]) {
    size_t bpos, dgbpos;
    size_t amt = min_sz(parent->mtu - HEADER_SIZE,
                        lstream->tx_buf_size);
    dg = datagram_create(lstream, amt + HEADER_SIZE);
    dg->tx_time = now;

    for(bpos = lstream->tx_buf_pos, dgbpos = HEADER_SIZE; amt; ) {
      size_t wamt = min_sz(TX_BUFFER_SIZE - bpos, amt);
      memcpy(dg->buf + dgbpos, lstream->tx_buf + bpos, wamt);
      bpos = (bpos + wamt) & (TX_BUFFER_SIZE - 1);
      dgbpos  += wamt;
      amt -= wamt;
    }

    /* Transmit the new datagram and adjust the MTU size as needed. */
    for(;;) {
      ssize_t res = TEMP_FAILURE_RETRY(
              send(parent->fd, dg->buf, dg->len, MSG_DONTWAIT));
      if(res == -1 && errno == EMSGSIZE) {
        /* Linux MTU discovery is telling us our packet is too large. */
        dg->len = --parent->mtu;
      } else {
        break;
      }
    }

    if(lstream->tx_buf_size == TX_BUFFER_SIZE) {
      pthread_cond_broadcast(&lstream->cond);
    }
    lstream->tx_buf_pos = (lstream->tx_buf_pos + dg->len - HEADER_SIZE) &
                          (TX_BUFFER_SIZE - 1);
    lstream->tx_buf_size -= dg->len - HEADER_SIZE;
  } else if(lstream->tx_heap.size) {
    dg = (struct datagram*)_mstream_heap_pop(&lstream->tx_heap);
    dg->tx_time = 0;

    /* Transmit packet.  Since we cannot adjust the size of the packet if the
     * set fails due to message size we allow fragmentation and try again. */
    ssize_t res = TEMP_FAILURE_RETRY(
            send(parent->fd, dg->buf, dg->len, MSG_DONTWAIT));
    if(res == -1 && errno == EMSGSIZE) {
      int oval;
      socklen_t len = sizeof(oval);
      getsockopt(parent->fd, IPPROTO_IP, IP_MTU_DISCOVER, &oval, &len);

      int val = IP_PMTUDISC_DONT;
      setsockopt(parent->fd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));
      TEMP_FAILURE_RETRY(send(parent->fd, dg->buf, dg->len, MSG_DONTWAIT));
      setsockopt(parent->fd, IPPROTO_IP, IP_MTU_DISCOVER, &oval, sizeof(oval));
    }
  } else {
    assert(lstream->ack_size);

    /* Send a pure ACK packet. */
    char buf[HEADER_SIZE];
    *(uint32_t*)buf = htonl(lstream->id);
    ((uint16_t*)buf)[2] = htons(0);
    ((uint16_t*)buf)[3] = htons(PARAM_CREATE(0, lstream->ack_size >= 1,
                                                lstream->ack_size >= 2));
    ((uint16_t*)buf)[4] = htons(pop_ack(lstream));
    ((uint16_t*)buf)[5] = htons(pop_ack(lstream));
    TEMP_FAILURE_RETRY(send(parent->fd, buf, HEADER_SIZE, MSG_DONTWAIT));
  }

  /* Insert the datagram into the retransmit heap. */
  if(dg) {
    /* Make sure tx_last is up to date.  It might not have been set if we
     * started out as a pure ACK. */
    parent->tx_last = max_time(parent->tx_last, lstream->tx_time);

    dg->rtx_time = now + _mstream_congestion_rtt(&parent->cinfo) +
              (time_val)sqrt(_mstream_congestion_rttvar(&parent->cinfo)) * 4;
    _mstream_heap_add(&lstream->rtx_heap, dg);
  }
}

static void acknowledge_packet(struct light_stream* lstream, uint16_t id,
                               time_val now) {
  struct mstream* parent = lstream->parent;
  struct datagram* dg = lstream->out_packets[id & (MAX_PACKETS - 1)];
  if(!dg || dg->tx_index != id) {
    return;
  }
  if(parent->congestion_event && lstream->id == parent->congestion_event_lid &&
     id == parent->congestion_event_pkt) {
    /* We got the packet that started a congestion event.  We can now cancel
     * the congestion event. */
    parent->congestion_event = 0;
  }

  _mstream_heap_remove(&lstream->rtx_heap, dg);
  _mstream_heap_remove(&lstream->tx_heap, dg);
  lstream->out_packets[id & (MAX_PACKETS - 1)] = NULL;

  if(!parent->congestion_event) {
    _mstream_congestion_ack(&lstream->parent->cinfo,
                            dg->tx_time ? now - dg->tx_time : 0);
  }

  free(dg);

  /* Check if we need to do a fast retransmit. */
  ++lstream->missed_acks;
  while(lstream->least_unacked_pkt != lstream->tx_seq_num &&
        !lstream->out_packets[lstream->least_unacked_pkt & (MAX_PACKETS - 1)]) {
    lstream->least_unacked_pkt++;
    lstream->missed_acks = 0;
  }
  if(lstream->missed_acks > 2) {
    struct datagram* dg = lstream->out_packets[lstream->least_unacked_pkt &
                                               (MAX_PACKETS -1)];
    if(!parent->congestion_event) {
      _mstream_congestion_rtx(&parent->cinfo);
      parent->congestion_event = 1;
      parent->congestion_event_lid = lstream->id;
      parent->congestion_event_pkt = lstream->least_unacked_pkt;
    }
    _mstream_heap_remove(&lstream->rtx_heap, dg);
    _mstream_heap_remove(&lstream->tx_heap, dg);
    _mstream_heap_add(&lstream->tx_heap, dg);
  }

  /* It's possible we've allowed a write to happen by ack'ing a packet. */
  recompute_times(lstream, now);
}

/* Internal libmstream functions. */
void _mstream_datagram_arrived(struct mstream* stream, const void* buf,
                               size_t amt, time_val now) {
  uint32_t id = ntohl(*(uint32_t*)buf);
  uint16_t pkt_id = ntohs(((uint16_t*)buf)[2]);
  uint16_t param = ntohs(((uint16_t*)buf)[3]);
  uint16_t ack_id1 = ntohs(((uint16_t*)buf)[4]);
  uint16_t ack_id2 = ntohs(((uint16_t*)buf)[5]);
  uint16_t len = PARAM_LENGTH(param);

  if(HEADER_SIZE + len != amt) {
    /* If length doesn't add up drop the packet. */
    return;
  }

  pthread_mutex_lock(&stream->lock);

  struct light_stream* lstream = stream_get_locked(stream, id);
  if(len == 0) {
    /* Pure ACK packet. */
    if(PARAM_HAS_ACK1(param)) {
      acknowledge_packet(lstream, ack_id1, now);
    }
    if(PARAM_HAS_ACK2(param)) {
      acknowledge_packet(lstream, ack_id2, now);
    }
  } else if(lstream && !lstream->packets[pkt_id & (MAX_PACKETS - 1)]) {
    if((int16_t)(pkt_id - lstream->packet_pos) < 0) {
      ack_packet(lstream, pkt_id);
    } else if(pkt_id - lstream->packet_pos < MAX_PACKETS) {
      ack_packet(lstream, pkt_id);

      struct rdatagram* dg = lstream->packets[pkt_id & (MAX_PACKETS - 1)] =
          (struct rdatagram*)malloc(offsetof(struct rdatagram, buf) + len);
      dg->len = len;
      dg->read_pos = 0;
      memcpy(dg->buf, ((const char*)buf) + HEADER_SIZE, len);

      if(pkt_id == lstream->packet_pos) {
        pthread_cond_broadcast(&lstream->cond);
      }

      if(PARAM_HAS_ACK1(param)) {
        acknowledge_packet(lstream, ack_id1, now);
      }
      if(PARAM_HAS_ACK2(param)) {
        acknowledge_packet(lstream, ack_id2, now);
      }
    }
  }

  pthread_mutex_unlock(&stream->lock);
}

void _mstream_transmit(struct light_stream* lstream, uint64_t now) {
  struct mstream* parent = lstream->parent;

  pthread_mutex_lock(&parent->lock);
  lstream->time = 0;

  /* Expire retransmits */
  while(lstream->rtx_heap.size > 0) {
    struct datagram* dg = (struct datagram*)
          _mstream_heap_top(&lstream->rtx_heap);
    if(time_less(now, dg->rtx_time)) {
      break;
    }
    if(!parent->congestion_event) {
      _mstream_congestion_rtx(&parent->cinfo);
      parent->congestion_event = 1;
      parent->congestion_event_lid = lstream->id;
      parent->congestion_event_pkt = dg->tx_index;
    }
    _mstream_heap_pop(&lstream->rtx_heap);
    _mstream_heap_add(&lstream->tx_heap, dg);
  }

  /* Attempt a write. */
  if(lstream->tx_time && time_less_eq(lstream->tx_time, now)) {
    transmit_packet(lstream, now);
    lstream->tx_time = 0;
  }

  recompute_times(lstream, now);

  if(lstream->time == 0) {
    /* Nothing to schedule, notify those waiting in flush. */
    pthread_cond_broadcast(&lstream->cond);
  }

  pthread_mutex_unlock(&parent->lock);
}

/* libmstream public API */

struct mstream* mstream_create(struct mdaemon* daemon, int fd) {
  struct mstream* stream = (struct mstream*)calloc(1, sizeof(struct mstream));
  stream->daemon = daemon;
  stream->fd = fd;
  stream->mtu = MAX_MTU;

  _mstream_congestion_init(&stream->cinfo);

  pthread_mutex_init(&stream->lock, NULL);
  pthread_cond_init(&stream->cond, NULL);
  _mstream_attach_stream(daemon, stream);
  return stream;
}

void mstream_destroy(struct mstream* stream) {
  size_t i;

  _mstream_detach_stream(stream->daemon, stream);
  for(i = 0; i < stream->streams_size; i++) {
    if(stream->streams[i]) {
      lstream_destroy(stream->streams[i]);
    }
  }
  free(stream->streams);
}

void mstream_flush(struct mstream* stream, uint32_t id) {
  size_t i;
  for(i = 0; i < stream->streams_size; i++) {
    if(stream->streams[i]) {
      lstream_flush(stream->streams[i]);
    }
  }
}

size_t mstream_write(struct mstream* stream, uint32_t id,
                     const void* buf, size_t len, int flags) {
  return lstream_write(stream_get(stream, id), buf, len, flags);
}

size_t mstream_read(struct mstream* stream, uint32_t* id,
                    void* buf, size_t len, int flags) {
  size_t res;
  if(*id == MSTREAM_IDANY) {
    pthread_mutex_lock(&stream->lock);
    for(res = 0; !res; ) {
      if(~flags & MSG_DONTWAIT) {
        while(!stream->ready_head) {
          pthread_cond_wait(&stream->cond, &stream->lock);
        }
      }
      if(!stream->ready_head) {
        *id = MSTREAM_IDANY;
        break;
      }

      int ready;
      struct light_stream* lstream = stream->ready_head;
      res = lstream_read(stream->ready_head, buf, len,
                         flags | MSG_DONTWAIT, &ready);
      *id = lstream->id;

      stream_list_pop_locked(stream);
      if(ready) {
        stream_list_push_locked(stream, lstream);
      }
    }
    pthread_mutex_unlock(&stream->lock);
  } else {
    res = lstream_read(stream_get(stream, *id), buf, len, flags, NULL);
  }
  return res;
}

struct mstream* mstream_listen(struct mdaemon* daemon, int fd,
                        struct sockaddr* src_addr, socklen_t* src_addrlen) {
  struct sockaddr addr;
  struct sockaddr bind_addr;
  socklen_t addrlen = sizeof(addr);
  socklen_t bind_addrlen = sizeof(bind_addr);

  char buf[MAX_MTU];
  ssize_t amt = TEMP_FAILURE_RETRY(recvfrom(fd, buf, sizeof(buf), 0,
                                            &addr, &addrlen));
  if(amt == -1) {
    return NULL;
  }

  if(src_addr && src_addrlen) {
    *src_addrlen = min_sz(*src_addrlen, addrlen);
    memcpy(src_addr, &addr, *src_addrlen);
  }

  int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(s == -1) {
    return NULL;
  }

  int val = 1;
  if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(int)) == -1) {
    close(s);
    return NULL;
  }

  addrlen = sizeof(addr);
  if(getsockname(fd, &bind_addr, &bind_addrlen) == -1) {
    close(s);
    return NULL;
  }

  if(bind(s, &bind_addr, bind_addrlen) == -1) {
    close(s);
    return NULL;
  }

  if(connect(s, &addr, addrlen) == -1) {
    close(s);
    return NULL;
  }

  struct mstream* stream = mstream_create(daemon, s);
  _mstream_datagram_arrived(stream, buf, amt, get_time());
  return stream;
}
