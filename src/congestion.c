#include "congestion.h"

#include <math.h>

void _mstream_congestion_init(struct congestion_info* cinfo) {
  cinfo->slow_start = 1;
  cinfo->rtt = 500000;
  cinfo->rtt_ssq = 1000000LL * 1000000LL;
  cinfo->spacing = cinfo->rtt / 10.0;
}

void _mstream_congestion_ack(struct congestion_info* cinfo, time_val rtt) {
  if(rtt) {
    cinfo->spacing /= cinfo->rtt;
    cinfo->rtt = ((cinfo->rtt << 6) - cinfo->rtt + rtt) >> 6;
    if(cinfo->rtt == 0) {
      cinfo->rtt = 1;
    }
    cinfo->spacing *= cinfo->rtt;
    cinfo->rtt_ssq = ((cinfo->rtt_ssq << 6) - cinfo->rtt_ssq + rtt * rtt) >> 6;
  }
  if(cinfo->slow_start) {
    cinfo->spacing = 1.0 / (1.0 / cinfo->spacing + 1.0 / cinfo->rtt);
  } else {
    cinfo->spacing = 1.0 / (1.0 / cinfo->spacing +
                            1.0 * cinfo->spacing / cinfo->rtt / cinfo->rtt);
  }
}

void _mstream_congestion_rtx(struct congestion_info* cinfo) {
  cinfo->slow_start = 0;
  cinfo->spacing *= 1.5;
  if(cinfo->spacing > 3e6) {
    cinfo->spacing = 3e6;
  }
}

time_val _mstream_congestion_rtt(struct congestion_info* cinfo) {
  return cinfo->rtt;
}

time_val _mstream_congestion_rttvar(struct congestion_info* cinfo) {
  return cinfo->rtt_ssq - cinfo->rtt * cinfo->rtt;
}

time_val _mstream_congestion_spacing(struct congestion_info* cinfo) {
  return (time_val)ceil(cinfo->spacing + 1e-9);
}
