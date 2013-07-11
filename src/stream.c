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

static const size_t HEADER_SIZE = 14;

struct rdatagram {
  size_t len;
  size_t read_pos;
  uint16_t id;
  char buf[1];
};

static void transmit_packet(struct light_stream* lstream, uint64_t now,
                            int ack_only);

static int datagram_compare_tx_order(void* px, void* py) {
  return (int16_t)(((struct datagram*)px)->tx_index -
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
  lstream->tx_tail = &lstream->tx;
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
    if((lstream->tx.buf_size &&
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
  } else if(!((lstream->tx.buf_size &&
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

  if(flags & MSTREAM_COPYNOW) {
    while(len) {
      amt = min_sz(len, TX_BUFFER_SIZE - lstream->tx_tail->buf_size);
      len -= amt;
      while(amt) {
        size_t pos = (lstream->tx_tail->buf_pos + lstream->tx_tail->buf_size) &
                        (TX_BUFFER_SIZE - 1);
        size_t wamt = min_sz(amt, TX_BUFFER_SIZE - pos);
        memcpy(lstream->tx_tail->buf + pos, cbuf, wamt);
        cbuf += wamt;
        amt -= wamt;
        lstream->tx_tail->buf_size += wamt;
      }

      if(len) {
        struct data_block* db = (struct data_block*)
            malloc(sizeof(struct data_block));
        db->buf_pos = 0;
        db->buf_size = 0;
        db->next = NULL;
        lstream->tx_tail->next = db;
        lstream->tx_tail = db;
      }
    }
  } else {
    if(~flags & MSG_DONTWAIT) {
      while(lstream->tx.buf_size == TX_BUFFER_SIZE) {
        pthread_cond_wait(&lstream->cond, &parent->lock);
      }
    }

    amt = min_sz(len, TX_BUFFER_SIZE - lstream->tx.buf_size);
    while(amt) {
      size_t pos = (lstream->tx.buf_pos + lstream->tx.buf_size) &
                      (TX_BUFFER_SIZE - 1);
      size_t wamt = min_sz(amt, TX_BUFFER_SIZE - pos);
      memcpy(lstream->tx.buf + pos, cbuf, wamt);
      cbuf += wamt;
      amt -= wamt;
      lstream->tx.buf_size += wamt;
    }
  }

  recompute_times(lstream, _mstream_get_time());
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
  transmit_packet(lstream, _mstream_get_time(), 1);
}

static size_t lstream_read_locked(struct light_stream* lstream, void* buf,
                                  size_t len, int flags, int* ready) {
  char* cbuf = (char*)buf;
  struct mstream* parent = lstream->parent;

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

    if(dg->read_pos == dg->len) {
      free(dg);
      lstream->packets[lstream->packet_pos & (MAX_PACKETS - 1)] = NULL;
      lstream->packet_pos++;
    }
  }
  if(ready) {
    *ready = lstream->packets[lstream->packet_pos & (MAX_PACKETS - 1)] != NULL;
  }
  return cbuf - (char*)buf;
}

static void lstream_flush(struct light_stream* lstream) {
  pthread_mutex_lock(&lstream->parent->lock);
  while(lstream->time || lstream->last_pkt_nxt != lstream->tx_seq_num) {
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
  /* Already in the ready list. */
  if(lstream->next) return;

  lstream->next = lstream;
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
    stream->ready_head = head->next;
    head->next = NULL;
  } else {
    head->next = stream->ready_head = stream->ready_tail = NULL;
  }
}

static uint16_t pop_ack(struct light_stream* lstream) {
  uint16_t ret = lstream->packet_read_next - 1;
  while(lstream->ack_size && (int16_t)(ret - lstream->packet_read_next) < 0) {
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
  dg->tx_count = 1;

  lstream->out_packets[dg->tx_index & (MAX_PACKETS - 1)] = dg;
  *(uint32_t*)dg->buf = htonl(lstream->id);
  ((uint16_t*)dg->buf)[2] = htons(dg->tx_index);
  ((uint16_t*)dg->buf)[3] = htons(len - HEADER_SIZE);
  ((uint16_t*)dg->buf)[4] = htons(lstream->packet_read_next);
  ((uint16_t*)dg->buf)[5] = htons(pop_ack(lstream));
  ((uint16_t*)dg->buf)[6] = htons(pop_ack(lstream));
  return dg;
}

static void transmit_packet(struct light_stream* lstream, uint64_t now,
                            int ack_only) {
  struct datagram* dg = NULL;
  struct mstream* parent = lstream->parent;
  if(!ack_only && lstream->tx.buf_size && lstream->tx_heap.size == 0 &&
     !lstream->out_packets[lstream->tx_seq_num & (MAX_PACKETS - 1)]) {
    size_t bpos, dgbpos;
    size_t amt = min_sz(parent->mtu - HEADER_SIZE,
                        lstream->tx.buf_size +
                        (lstream->tx.next ? lstream->tx.next->buf_size : 0U));
    dg = datagram_create(lstream, amt + HEADER_SIZE);
    dg->tx_time = now;

    struct data_block* db = &lstream->tx;
    for(dgbpos = HEADER_SIZE; amt; db = db->next) {
      size_t tamt = min_sz(amt, db->buf_size);
      amt -= tamt;

      for(bpos = db->buf_pos; tamt; ) {
        size_t wamt = min_sz(TX_BUFFER_SIZE - bpos, tamt);
        memcpy(dg->buf + dgbpos, db->buf + bpos, wamt);
        bpos = (bpos + wamt) & (TX_BUFFER_SIZE - 1);
        dgbpos += wamt;
        tamt -= wamt;
      }
    }

    /* Transmit the new datagram and adjust the MTU size as needed. */
    for(;;) {
      ssize_t res = TEMP_FAILURE_RETRY(send(parent->fd, dg->buf, dg->len,
                                            MSG_DONTWAIT));
      if(res == -1 && errno == EMSGSIZE) {
        /* Linux MTU discovery is telling us our packet is too large. */
        dg->len = --parent->mtu;
        ((uint16_t*)dg->buf)[3] = htons(dg->len - HEADER_SIZE);
      } else {
        break;
      }
    }

    amt = dg->len - HEADER_SIZE;
    while(amt) {
      if(!lstream->tx.next && lstream->tx.buf_size == TX_BUFFER_SIZE) {
        pthread_cond_broadcast(&lstream->cond);
      }

      size_t tamt = min_sz(amt, lstream->tx.buf_size);
      lstream->tx.buf_pos = (lstream->tx.buf_pos + tamt) &
                            (TX_BUFFER_SIZE - 1);
      lstream->tx.buf_size -= tamt;
      amt -= tamt;

      if(lstream->tx.buf_size == 0 && lstream->tx.next) {
        struct data_block* db = lstream->tx.next;
        memcpy(&lstream->tx, db, sizeof(struct data_block));
        free(db);

        if(!lstream->tx.next) {
          lstream->tx_tail = &lstream->tx;
        }
      }
    }
  } else if(!ack_only && lstream->tx_heap.size) {
    dg = (struct datagram*)_mstream_heap_pop(&lstream->tx_heap);
    ((uint16_t*)dg->buf)[4] = htons(lstream->packet_read_next);
    ((uint16_t*)dg->buf)[5] = htons(pop_ack(lstream));
    ((uint16_t*)dg->buf)[6] = htons(pop_ack(lstream));
    dg->tx_time = 0;

    ssize_t res;
    if(++dg->tx_count >= 3 && dg->len < parent->mtu) {
      size_t extra_len = parent->mtu - dg->len;
      void* extra = alloca(extra_len);
      memset(extra, 0, extra_len);
      TEMP_FAILURE_RETRY(send(parent->fd, dg->buf, dg->len, MSG_MORE));
      res = TEMP_FAILURE_RETRY(send(parent->fd, extra, extra_len,
                                    MSG_DONTWAIT));
    } else {
      res = TEMP_FAILURE_RETRY(send(parent->fd, dg->buf, dg->len,
                                    MSG_DONTWAIT));
    }
    if(res == -1 && errno == EMSGSIZE) {
      int oval;
      socklen_t len = sizeof(oval);
      getsockopt(parent->fd, IPPROTO_IP, IP_MTU_DISCOVER, &oval, &len);

      int val = IP_PMTUDISC_DONT;
      setsockopt(parent->fd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));
      TEMP_FAILURE_RETRY(send(parent->fd, dg->buf, dg->len,
                              MSG_DONTWAIT));
      setsockopt(parent->fd, IPPROTO_IP, IP_MTU_DISCOVER, &oval, sizeof(oval));
    }
  } else {
    /* Send a pure ACK packet. */
    char buf[HEADER_SIZE];
    *(uint32_t*)buf = htonl(lstream->id);
    ((uint16_t*)buf)[2] = htons(0);
    ((uint16_t*)buf)[3] = htons(0);
    ((uint16_t*)buf)[4] = htons(lstream->packet_read_next);
    ((uint16_t*)buf)[5] = htons(pop_ack(lstream));
    ((uint16_t*)buf)[6] = htons(pop_ack(lstream));
    TEMP_FAILURE_RETRY(send(parent->fd, buf, HEADER_SIZE, MSG_DONTWAIT));
  }

  /* Insert the datagram into the retransmit heap. */
  if(dg) {
    /* Make sure tx_last is up to date.  It might not have been set if we
     * started out as a pure ACK. */
    parent->tx_last = max_time(parent->tx_last, now);

    dg->rtx_time = now + _mstream_congestion_rtt(&parent->cinfo) + 5000 +
              (time_val)sqrt(_mstream_congestion_rttvar(&parent->cinfo)) * 4;
    _mstream_heap_add(&lstream->rtx_heap, dg);
  }
}

static int acknowledge_packet(struct light_stream* lstream, uint16_t id,
                              time_val now, int use_rtt) {
  struct mstream* parent = lstream->parent;
  struct datagram* dg = lstream->out_packets[id & (MAX_PACKETS - 1)];
  if(!dg || dg->tx_index != id || (int16_t)(id - lstream->last_pkt_nxt) < 0) {
    return 0;
  }

  _mstream_heap_remove(&lstream->rtx_heap, dg);
  _mstream_heap_remove(&lstream->tx_heap, dg);
  lstream->out_packets[id & (MAX_PACKETS - 1)] = NULL;

  if(dg->tx_time && use_rtt) {
static time_val stime = 0;
if(!stime) {
stime = now;
}
printf("ACK %u - %u %p %zu %llu\n", lstream->id, id, dg, dg->tx_index,
                            now - stime);
    _mstream_congestion_ack(&lstream->parent->cinfo, now - dg->tx_time, now);
  }

  free(dg);

  /* It's possible we've allowed a write to happen by ack'ing a packet. */
  recompute_times(lstream, now);

  return 1;
}

/* Internal libmstream functions. */
void _mstream_datagram_arrived(struct mstream* stream, const void* buf,
                               size_t amt, time_val now) {
  uint32_t id = ntohl(*(uint32_t*)buf);
  uint16_t pkt_id = ntohs(((uint16_t*)buf)[2]);
  uint16_t len = ntohs(((uint16_t*)buf)[3]);
  uint16_t pkt_nxt = ntohs(((uint16_t*)buf)[4]);
  uint16_t ack_id1 = ntohs(((uint16_t*)buf)[5]);
  uint16_t ack_id2 = ntohs(((uint16_t*)buf)[6]);

  if(HEADER_SIZE + len != amt) {
    /* If length doesn't add up drop the packet.  To get around some filtering
     * rules we sometimes increase the size of the packet and pad with zeroes.
     */
    if(HEADER_SIZE + len < amt) {
      size_t extra_len = amt - (HEADER_SIZE + len);
      char* extra_base = (char*)buf + amt - extra_len;

      if(*extra_base || memcmp(extra_base, extra_base + 1, extra_len - 1)) {
        return;
      }
    } else {
      return;
    }
  }

  pthread_mutex_lock(&stream->lock);

  int fresh_data = 0;
  struct light_stream* lstream = stream_get_locked(stream, id);

  if(lstream->future_acks) {
    stream->congested_streams--;
  }

  int use_ack = 1;
  for(; (int16_t)(lstream->last_pkt_nxt - pkt_nxt) < 0; use_ack = 0) {
    if(!acknowledge_packet(lstream, lstream->last_pkt_nxt, now, use_ack)) {
      --lstream->future_acks;
    }
    if(lstream->tx_seq_num == ++lstream->last_pkt_nxt) {
      pthread_cond_broadcast(&lstream->cond);
    }
  }
  if(acknowledge_packet(lstream, ack_id1, now, 1)) {
    ++lstream->future_acks;
  }
  if(acknowledge_packet(lstream, ack_id2, now, 1)) {
    ++lstream->future_acks;
  }

  if(lstream->future_acks) {
    stream->congested_streams++;
  }
  if(stream->congested_streams == 0) {
    stream->congestion_event = 0;
  }

  if(len && lstream) {
    if((uint16_t)(pkt_id - lstream->packet_pos) < MAX_PACKETS &&
              !lstream->packets[pkt_id & (MAX_PACKETS - 1)]) {
      struct rdatagram* dg = lstream->packets[pkt_id & (MAX_PACKETS - 1)] =
          (struct rdatagram*)malloc(offsetof(struct rdatagram, buf) + len);
      dg->len = len;
      dg->read_pos = 0;
      dg->id = pkt_id;
      memcpy(dg->buf, ((const char*)buf) + HEADER_SIZE, len);

      if(pkt_id == lstream->packet_pos) {
        fresh_data = 1;
        pthread_cond_broadcast(&lstream->cond);
      }

      while(1) {
        struct rdatagram* dg =
            lstream->packets[lstream->packet_read_next & (MAX_PACKETS - 1)];
        if(!dg || dg->id != lstream->packet_read_next) {
          break;
        }
        ++lstream->packet_read_next;
      }
    }
    if((int16_t)(pkt_id - lstream->packet_pos) < (int16_t)MAX_PACKETS) {
      ack_packet(lstream, pkt_id);
    }
  }

  /* Check if we need to do a fast retransmit. */
  if(!stream->congestion_event && lstream->future_acks >= 3) {
    struct datagram* dg = (struct datagram*)
        lstream->out_packets[pkt_nxt & (MAX_PACKETS - 1)];
    if(dg) {
      _mstream_congestion_rtx(&stream->cinfo);
      stream->congestion_event = 1;

      _mstream_heap_remove(&lstream->rtx_heap, dg);
      _mstream_heap_remove(&lstream->tx_heap, dg);
      _mstream_heap_add(&lstream->tx_heap, dg);

      recompute_times(lstream, now);
    }
  }

  if(fresh_data) {
    stream_list_push_locked(stream, lstream);
  }
  pthread_mutex_unlock(&stream->lock);

  if(fresh_data && stream->arrival_func) {
    stream->arrival_func(stream, id);
  }
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
    /* RTOs should always trigger a congestion event so that we'll always back
     * off if the remote stops responding. */

    if(dg->tx_index == lstream->last_pkt_nxt) {
      _mstream_congestion_rto(&parent->cinfo);
      //parent->congestion_event = 1;
    }

printf("RTOOO\n");
    _mstream_heap_pop(&lstream->rtx_heap);
    _mstream_heap_add(&lstream->tx_heap, dg);
  }

  /* Attempt a write. */
  if(lstream->tx_time && time_less_eq(lstream->tx_time, now)) {
    transmit_packet(lstream, now, 0);
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

struct mstream* mstream_create(struct mdaemon* daemon, int fd,
                               data_arrival arrival_func) {
  struct mstream* stream = (struct mstream*)calloc(1, sizeof(struct mstream));
  stream->daemon = daemon;
  stream->fd = fd;
  stream->arrival_func = arrival_func;
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
  close(stream->fd);
  free(stream);
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
  pthread_mutex_lock(&stream->lock);
  if(*id == MSTREAM_IDANY) {
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
      res = lstream_read_locked(stream->ready_head, buf, len,
                                flags | MSG_DONTWAIT, &ready);
      *id = lstream->id;

      stream_list_pop_locked(stream);
      if(ready) {
        stream_list_push_locked(stream, lstream);
      }
    }
  } else {
    res = lstream_read_locked(stream_get(stream, *id), buf, len, flags, NULL);
  }
  pthread_mutex_unlock(&stream->lock);
  return res;
}

void mstream_info(struct mstream* stream, struct stream_info* info) {
  info->rtt = _mstream_congestion_rtt(&stream->cinfo);
  info->rttvar = (time_val)sqrt(_mstream_congestion_rttvar(&stream->cinfo));
}

struct mstream* mstream_listen(struct mdaemon* daemon, int fd,
                        struct sockaddr* src_addr, socklen_t* src_addrlen,
                        data_arrival arrival_func) {
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

  struct mstream* stream = mstream_create(daemon, s, arrival_func);
  _mstream_datagram_arrived(stream, buf, amt, _mstream_get_time());
  return stream;
}
