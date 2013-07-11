#ifndef MSTREAM_MSTREAM_H
#define MSTREAM_MSTREAM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <sys/socket.h>
#include <sys/types.h>

#define MSTREAM_IDANY 0xFFFFFFFFU

#define MSTREAM_COPYNOW 0x00010000U

struct mdaemon;
struct mstream;

typedef void(*data_arrival)(struct mstream*, uint32_t);

typedef uint64_t time_val;

struct stream_info {
  time_val rtt;
  time_val rttvar;
};

struct mdaemon* mstream_daemon_create();
void mstream_daemon_start(struct mdaemon* daemon);
void mstream_daemon_stop(struct mdaemon* daemon);
void mstream_daemon_destroy(struct mdaemon* daemon);

struct mstream* mstream_listen(struct mdaemon* daemon, int fd,
                               struct sockaddr* src_addr, socklen_t* addrlen,
                               data_arrival arrival_func);

struct mstream* mstream_create(struct mdaemon* daemon, int fd,
                               data_arrival arrival_func);

void mstream_destroy(struct mstream* stream);

void mstream_flush(struct mstream* stream, uint32_t id);

size_t mstream_write(struct mstream* stream, uint32_t id,
                     const void* buf, size_t len, int flags);

size_t mstream_read(struct mstream* stream, uint32_t* id,
                    void* buf, size_t len, int flags);

void mstream_info(struct mstream* stream, struct stream_info* info);

#ifdef __cplusplus
}
#endif

#endif
