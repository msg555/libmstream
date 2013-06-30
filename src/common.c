#include "common.h"

#include <sys/time.h>

time_val get_time() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec * 1000000ULL + tv.tv_usec;
}
