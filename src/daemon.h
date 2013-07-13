#ifndef MSTREAM_DAEMON_H
#define MSTREAM_DAEMON_H

#include "common.h"
#include "heap.h"

#include <pthread.h>

#include <errno.h>
#include <unistd.h>

#ifndef TEMP_FAILURE_RETRY
/* Used to retry syscalls that can return EINTR. */
#define TEMP_FAILURE_RETRY(exp) ({         \
    typeof (exp) _rc;                      \
    do {                                   \
        _rc = (exp);                       \
    } while (_rc == -1 && errno == EINTR); \
    _rc; })
#endif

struct mstream;
struct light_stream;

struct mdaemon {
  struct heap timer_heap;

  int epollfd;
  int timerfd;

  time_val cur_timer;

  pthread_mutex_t lock;

  int thread_shutdown;
  pthread_t thread;
};

void _mstream_attach_stream(struct mdaemon* daemon, struct mstream* stream);
void _mstream_detach_stream(struct mdaemon* daemon, struct mstream* stream);

void _mstream_daemon_adjust_timer(struct mdaemon* daemon);

#endif
