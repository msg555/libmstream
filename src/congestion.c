#include "congestion.h"

#include <math.h>

void _mstream_congestion_init(struct congestion_info* cinfo) {
  cinfo->slow_start = 0;
  cinfo->rtt = 200000;
  cinfo->rtt_ssq = 400000LL * 400000LL;
  cinfo->rtt_trigger = 250000;
  cinfo->rtt_trigger_next = 0;
  cinfo->spacing = cinfo->rtt / 10.0;
}

void _mstream_congestion_ack(struct congestion_info* cinfo, time_val rtt,
                             time_val now) {
  if(rtt) {
// printf("GOT RTT %llu %llu\n", cinfo->rtt, rtt);
    int shft = cinfo->slow_start ? 2 : 4;
    if(!cinfo->slow_start) {
      /* Don't allow rtt to grow too quickly. */
      rtt = min_time(rtt, cinfo->rtt << 1);
    }

    cinfo->spacing /= cinfo->rtt;
    cinfo->rtt = ((cinfo->rtt << shft) - cinfo->rtt + rtt) >> shft;
    if(cinfo->rtt == 0) {
      cinfo->rtt = 1;
    }
    cinfo->spacing *= cinfo->rtt;
    cinfo->rtt_ssq = ((cinfo->rtt_ssq << shft) -
                        cinfo->rtt_ssq + rtt * rtt) >> shft;

    if(!cinfo->slow_start) {
      if((cinfo->rtt_trigger_next == 0 ||
          (stime_val)(now - cinfo->rtt_trigger_next) >= 0) &&
         cinfo->rtt >= cinfo->rtt_trigger) {
printf("RTT BACKOFF\n");
        cinfo->spacing *= 1.3;
        if(cinfo->spacing > 3e6) {
          cinfo->spacing = 3e6;
        }
        cinfo->rtt_trigger = cinfo->rtt + (cinfo->rtt >> 2) + 1000;
        cinfo->rtt_trigger_next = now + (cinfo->rtt << 1);
      } else {
        cinfo->rtt_trigger = min_time(cinfo->rtt_trigger,
                                      cinfo->rtt + (cinfo->rtt >> 2) + 1000);
      }
    }
  }
  if(cinfo->slow_start) {
    if(cinfo->spacing > cinfo->rtt / 10.0) {
      cinfo->spacing = cinfo->rtt / 10.0;
    }
    if(rtt && cinfo->spacing > rtt / 10.0) {
      cinfo->spacing = rtt / 10.0;
    }
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

void _mstream_congestion_rto(struct congestion_info* cinfo) {
printf("RTO\n");
  //cinfo->slow_start = 1;
  cinfo->spacing = cinfo->rtt / 10.0;
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
