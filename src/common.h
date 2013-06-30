#ifndef MSTREAM_COMMON_H
#define MSTREAM_COMMON_H

#include <stddef.h>
#include <stdint.h>

      #include <stdio.h>

#ifdef __GNUC__
#define MAYBE_UNUSED __attribute__ ((unused))
#else
#define MAYBE_UNUSED
#endif

typedef uint64_t time_val;
typedef int64_t stime_val;

/* The maximum number of un-acked packets that can be sent/received. */
#define MAX_PACKETS (1UL << 10)

/* The maximum number of bytes help in libmstream in preparation to send. */
#define TX_BUFFER_SIZE (1UL << 12)

/* Indicates the largest MTU to try. If this frame size causes fragmentation,
 * as calculated by the operating system, the transmit size will be lowered. */
#define MAX_MTU 1500

MAYBE_UNUSED
static size_t min_sz(size_t x, size_t y) {
  return x < y ? x : y;
}

MAYBE_UNUSED
static int time_less(time_val x, time_val y) {
  return (stime_val)(x - y) < 0;
}

MAYBE_UNUSED
static int time_less_eq(time_val x, time_val y) {
  return (stime_val)(x - y) <= 0;
}

MAYBE_UNUSED
static time_val min_time(time_val x, time_val y) {
  return time_less(x, y) ? x : y;
}

MAYBE_UNUSED
static time_val max_time(time_val x, time_val y) {
  return time_less(x, y) ? y : x;
}

time_val get_time();

#endif
