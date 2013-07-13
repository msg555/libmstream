#include "common.h"
#include "daemon.h"
#include "stream.h"

#include <mstream.h>

#include <pthread.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

static const size_t MAX_EVENTS = 32;

static int timer_compare(void* px, void *py) {
  return (int64_t)(((struct timer_info*)px)->time -
                   ((struct timer_info*)py)->time) < 0;
}

static size_t timer_get_heap_id(void* x) {
  return ((struct timer_info*)x)->heap_id;
}

static void timer_set_heap_id(void* x, size_t id) {
  ((struct timer_info*)x)->heap_id = id;
}

static void* daemon_thread(void* parg) {
  char buf[MAX_MTU];
  struct epoll_event events[MAX_EVENTS],* ei,* ee;
  struct mdaemon* self;

  self = (struct mdaemon*)parg;
  for(; !self->thread_shutdown; ) {
    int nfds = TEMP_FAILURE_RETRY(
                          epoll_wait(self->epollfd, events, MAX_EVENTS, -1));
    if(nfds == -1) {
      break;
    }

    time_val now = _mstream_get_time();
    for(ei = events, ee = events + nfds; ei != ee; ++ei) {
      if(ei->data.ptr == NULL) {
        /* NULL data pointer indicates a timer expiration. */
        for(;;) {
          if(TEMP_FAILURE_RETRY(read(self->timerfd, buf, sizeof(buf))) == -1) {
            break;
          }
        }

        /* Process any timer expirations allowing writes/retransmits. */
        pthread_mutex_lock(&self->lock);
        if(self->cur_timer) {
          now = max_time(now, self->cur_timer);
          self->cur_timer = 0;
          while(self->timer_heap.size) {
            struct timer_info* tinfo = (struct timer_info*)
                _mstream_heap_top(&self->timer_heap);
            if(time_less(now, tinfo->time)) {
              break;
            }

            pthread_mutex_unlock(&self->lock);
            tinfo->timer_expired(tinfo, now);
            pthread_mutex_lock(&self->lock);
          }
          _mstream_daemon_adjust_timer(self);
        }
        pthread_mutex_unlock(&self->lock);

      } else {
        struct mstream* stream = (struct mstream*)ei->data.ptr;
        ssize_t amt = TEMP_FAILURE_RETRY(recv(stream->fd, buf, sizeof(buf), 0));
        if(amt > 0) {
          _mstream_datagram_arrived(stream, buf, amt, now);
        }
      }
    }
  }
  return NULL;
}

/* Internal libmstream functions. */
void _mstream_attach_stream(struct mdaemon* daemon, struct mstream* stream) {
  struct epoll_event ev;
  memset(&ev, 0, sizeof(ev));
  ev.events = EPOLLIN;
  ev.data.ptr = stream;
  epoll_ctl(daemon->epollfd, EPOLL_CTL_ADD, stream->fd, &ev);
}

void _mstream_detach_stream(struct mdaemon* daemon, struct mstream* stream) {
  // struct epoll_event ev;
  // epoll_ctl(daemon->epollfd, EPOLL_CTL_DEL, stream->fd, &ev);
}

void _mstream_daemon_adjust_timer(struct mdaemon* daemon) {
  time_val ntime = !daemon->timer_heap.size ? 0 :
        ((struct timer_info*)_mstream_heap_top(&daemon->timer_heap))->time;
  if(daemon->thread_shutdown) {
    ntime = _mstream_get_time();
  }
  if(ntime != daemon->cur_timer) {
    struct itimerspec ispec;
    daemon->cur_timer = ntime;

    time_val time_rel = ntime - _mstream_get_time();
    if((stime_val)time_rel <= 0) time_rel = 1;

    ispec.it_interval.tv_sec = 0;
    ispec.it_interval.tv_nsec = 0;
    ispec.it_value.tv_sec = time_rel / 1000000;
    ispec.it_value.tv_nsec = (time_rel % 1000000) * 1000;
    _mstream_timerfd_settime(daemon->timerfd, 0, &ispec, NULL);
  }
}

/* libmstream public API */
struct mdaemon* mstream_daemon_create() {
  struct mdaemon* daemon = (struct mdaemon*)calloc(1, sizeof(struct mdaemon));
  daemon->epollfd = epoll_create(10);
  daemon->timerfd = _mstream_timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);

  struct epoll_event ev;
  memset(&ev, 0, sizeof(ev));
  ev.events = EPOLLIN;
  epoll_ctl(daemon->epollfd, EPOLL_CTL_ADD, daemon->timerfd, &ev);

  pthread_mutex_init(&daemon->lock, NULL);
  _mstream_heap_init(&daemon->timer_heap, timer_compare,
                     timer_get_heap_id, timer_set_heap_id);
  return daemon;
}

void mstream_daemon_start(struct mdaemon* daemon) {
  pthread_create(&daemon->thread, NULL, daemon_thread, daemon);
}

void mstream_daemon_stop(struct mdaemon* daemon) {
  daemon->thread_shutdown = 1;
  _mstream_daemon_adjust_timer(daemon);

  pthread_join(daemon->thread, NULL);
  daemon->thread_shutdown = 0;
}

void mstream_daemon_destroy(struct mdaemon* daemon) {
  mstream_daemon_stop(daemon);
  close(daemon->epollfd);
  close(daemon->timerfd);
  pthread_mutex_destroy(&daemon->lock);
  _mstream_heap_destroy(&daemon->timer_heap);
  free(daemon);
}
