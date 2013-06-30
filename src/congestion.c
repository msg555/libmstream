#include "congestion.h"

void _mstream_congestion_init(struct congestion_info* cinfo) {
  cinfo->slow_start = 1;
  cinfo->spacing = cinfo->rtt = 500000;
  cinfo->rtt_ssq = 1000000LL * 1000000LL;
}

void _mstream_congestion_ack(struct congestion_info* cinfo, time_val rtt) {
  if(rtt) {
    cinfo->rtt = ((cinfo->rtt << 6) - cinfo->rtt + rtt) >> 6;
    if(cinfo->rtt == 0) {
      cinfo->rtt = 1;
    }
    cinfo->rtt_ssq = ((cinfo->rtt_ssq << 6) - cinfo->rtt_ssq + rtt * rtt) >> 6;
  }
  if(cinfo->slow_start) {
    cinfo->spacing = 1.0 / (1.0 / cinfo->rtt + 1.0 / cinfo->spacing);
  } else {
    cinfo->spacing = (cinfo->spacing >> 1) + 1;
  }
}

void _mstream_congestion_rtx(struct congestion_info* cinfo) {
  cinfo->slow_start = 0;
  cinfo->spacing = min_time(cinfo->rtt, cinfo->spacing * 3 / 2 + 1);
}

time_val _mstream_congestion_rtt(struct congestion_info* cinfo) {
  return cinfo->rtt;
}

time_val _mstream_congestion_rttvar(struct congestion_info* cinfo) {
  return cinfo->rtt_ssq - cinfo->rtt * cinfo->rtt;
}

time_val _mstream_congestion_spacing(struct congestion_info* cinfo) {
  return cinfo->spacing;
}
