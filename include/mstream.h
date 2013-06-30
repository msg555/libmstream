#ifndef MSTREAM_MSTREAM_H
#define MSTREAM_MSTREAM_H

#include <stdint.h>

#include <sys/socket.h>
#include <sys/types.h>

#define MSTREAM_IDANY 0xFFFFFFFFU

struct mdaemon* mstream_daemon_create();
void mstream_daemon_start(struct mdaemon* daemon);
void mstream_daemon_stop(struct mdaemon* daemon);
void mstream_daemon_destroy(struct mdaemon* daemon);

struct mstream* mstream_listen(struct mdaemon* daemon, int fd,
                               struct sockaddr* src_addr, socklen_t* addrlen);

struct mstream* mstream_create(struct mdaemon* daemon, int fd);

void mstream_destroy(struct mstream* stream);

void mstream_flush(struct mstream* stream, uint32_t id);

size_t mstream_write(struct mstream* stream, uint32_t id,
                     const void* buf, size_t len, int flags);

size_t mstream_read(struct mstream* stream, uint32_t* id,
                    void* buf, size_t len, int flags);

#endif
