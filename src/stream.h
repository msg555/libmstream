#ifndef MSTREAM_STREAM_H
#define MSTREAM_STREAM_H

#include <stdint.h>

#include "common.h"
#include "congestion.h"
#include "heap.h"

#include <mstream.h>

struct mdaemon;
struct mstream;
struct rdatagram;

struct datagram {
  size_t tx_index;
  size_t tx_heap_id;
  size_t rtx_heap_id;

  size_t tx_count;
  time_val tx_time;

  size_t len;
  char buf[1];
};

struct data_block {
  struct data_block* next;
  size_t buf_pos;
  size_t buf_size;
  char buf[TX_BUFFER_SIZE];
};

struct timer_info {
  time_val time;
  size_t heap_id;
  void (*timer_expired)(struct timer_info*, time_val);
};

struct light_stream {
  struct timer_info tx_timer;

  struct mstream* parent;
  uint32_t id;

  pthread_cond_t cond;

  struct light_stream* pending_next;
  struct light_stream* ready_next;

  uint16_t tx_seq_num;
  uint16_t packet_read_next;

  struct heap tx_heap;
  struct heap rtx_heap;

  uint16_t last_pkt_nxt;
  uint16_t future_acks;

  size_t ack_pos;
  size_t ack_size;
  uint16_t ack_list[MAX_PACKETS];

  uint16_t packet_pos;
  struct rdatagram* packets[MAX_PACKETS];
  struct datagram* out_packets[MAX_PACKETS];

  struct data_block* tx_tail;
  struct data_block tx;
};

struct mstream {
  struct timer_info rto_timer;

  struct mdaemon* daemon;
  int fd;
  data_arrival arrival_func;

  size_t streams_size;
  struct light_stream** streams;

  time_val tx_last;

  struct congestion_info cinfo;
  int congestion_event;
  uint32_t congested_streams;
  uint16_t mtu;

  pthread_mutex_t lock;
  pthread_cond_t cond;

  struct light_stream* pending_head;
  struct light_stream* pending_tail;
  struct light_stream* ready_head;
  struct light_stream* ready_tail;
};

void _mstream_datagram_arrived(struct mstream* stream, const void* buf,
                               size_t amt, time_val now);

#endif
