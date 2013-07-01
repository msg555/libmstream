#include "common.h"

#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

#if !defined(SYS_timerfd_create) || !defined(SYS_timerfd_settime)
# if defined(__i386__)
#  define SYS_timerfd_create 322
#  define SYS_timerfd_settime 325
# elif defined(__x86_64__)
#  define SYS_timerfd_create 283 /* Syscall numbers are same for x86 and x32 */
#  define SYS_timerfd_settime 286
# elif defined(__arm__)
#  define SYS_timerfd_create 350 /* Syscall numbers are same for x86 and x32 */
#  define SYS_timerfd_settime 353
# else
#  error "no timerfd"
# endif
#endif

int _mstream_timerfd_create(int clockid, int flags) {
  return syscall(SYS_timerfd_create, clockid, flags);
}

int _mstream_timerfd_settime(int fd, int flags,
                     const struct itimerspec* new_value,
                     struct itimerspec* old_value) {
  return syscall(SYS_timerfd_settime, fd, flags, new_value, old_value);
}

time_val _mstream_get_time() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec * 1000000ULL + tv.tv_usec;
}
