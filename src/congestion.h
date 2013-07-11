#ifndef MSTREAM_CONGESTION_H
#define MSTREAM_CONGESTION_H

#include "common.h"

struct congestion_info {
  int slow_start;
  time_val rtt;
  time_val rtt_ssq;
  time_val rtt_trigger;
  time_val rtt_trigger_next;
  double spacing;
};

void _mstream_congestion_init(struct congestion_info* cinfo);

void _mstream_congestion_ack(struct congestion_info* cinfo, time_val rtt,
                             time_val now);

void _mstream_congestion_rtx(struct congestion_info* cinfo);

void _mstream_congestion_rto(struct congestion_info* cinfo);

time_val _mstream_congestion_rtt(struct congestion_info* cinfo);

time_val _mstream_congestion_rttvar(struct congestion_info* cinfo);

time_val _mstream_congestion_spacing(struct congestion_info* cinfo);

#endif
