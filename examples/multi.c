#include <mstream.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <stdio.h>
#include <string.h>

#define IDS 16
#define ROUNDS 1024

void print_usage(FILE* fout, const char* argv0) {
  fprintf(fout, "usage: %s [options] [host:]port\n"
                 "  [host:] is not optional when running in client mode\n"
                 "--host          Run host client.\n", argv0);
}

void data(struct mstream* stream, uint32_t id) {
}

int main(int argc, char** argv) {
  int is_host = 0;
  char* argv0 = argv[0];
  while(argc > 1 && *argv[1] == '-') {
    if(!strcmp(argv[1], "--host")) {
      is_host = 1;
    } else if(!strcmp(argv[1], "--help")) {
      print_usage(stdout, argv0);
    } else {
      fprintf(stderr, "Unknown flag '%s'\n", argv[1]);
      print_usage(stderr, argv0);
      return 1;
    }
    ++argv; --argc;
  }
  if(argc < 2) {
    print_usage(stderr, argv0);
    return 1;
  }

  int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(s == -1) {
    perror("socket");
    return 1;
  }

  int val = 1;
  if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(int)) == -1) {
    perror("setsockopt");
    return 1;
  }

  char* str;
  char* addr = NULL;
  char* port = argv[1];
  for(str = argv[1]; *str; ++str) {
    if(*str == ':') {
      *str = 0;
      addr = argv[1];
      port = str + 1;
    }
  }

  if(!is_host && !addr) {
    fprintf(stderr, "[host:] must be present when running as client\n");
    return 1;
  }

  int res;
  struct addrinfo hints;
  struct addrinfo* addrinf;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = addr ? 0 : AI_PASSIVE;
  if((res = getaddrinfo(addr, port, &hints, &addrinf))) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(res));
    return 1;
  }
  if(!addrinf) {
    fprintf(stderr, "could not get address info\n");
    return 1;
  }

  struct mdaemon* daemon = mstream_daemon_create();
  mstream_daemon_start(daemon);

  struct mstream* stream;
  if(is_host) {
    if(bind(s, addrinf->ai_addr, addrinf->ai_addrlen) == -1) {
      perror("bind");
      return 1;
    }
    stream = mstream_listen(daemon, s, NULL, NULL, data);

    if(!stream) {
      printf("mstream_listen failed\n");
      return 1;
    }

    printf("connection received\n");
  } else {
    if(connect(s, addrinf->ai_addr, addrinf->ai_addrlen) == -1) {
      perror("connect");
      return 1;
    }
    stream = mstream_create(daemon, s, data);
  }

  size_t i, j;
  unsigned char buf[IDS][1001];

  for(i = 0; i < IDS; i++) {
    for(j = 0; j < sizeof(buf[i]); j++) {
      buf[i][j] = (i + j) & 0xFF;
    }
  }
  for(j = 0; j < ROUNDS; j++) {
    for(i = 0; i < IDS; i++) {
      size_t pos = 0;
      while(pos < sizeof(buf[i])) {
        pos += mstream_write(stream, i & 127, (char*)buf[i] + pos,
                             sizeof(buf[i]) - pos, MSTREAM_COPYNOW);
      }
    }
  }

printf("READING\n");
  size_t finished = 0;
  size_t received[IDS] = {0};
  for(; finished < IDS; ) {
    unsigned char rbuf[1001];
    uint32_t id = MSTREAM_IDANY;
    size_t amt = mstream_read(stream, &id, (char*)rbuf, sizeof(rbuf), 0);

    int doprint = 0;
    for(i = 0; i < amt; i++) {
      if(rbuf[i] != buf[id][received[id]++ % sizeof(buf[id])]) {
        fprintf(stderr, "bad transmit\n");
        return 1;
      }
      doprint |= !((received[id]/sizeof(buf[id]))&0xF);
    }
    if(doprint)printf("Read %u\n", id);
    if(received[id] == ROUNDS * sizeof(buf[id])) {
      finished++;
    }
  }
  mstream_flush(stream, MSTREAM_IDANY);

  struct stream_info info;
  mstream_info(stream, &info);
  printf("RTT: %lld\n", (long long)info.rtt);
  printf("RTTVAR: %lld\n", (long long)info.rttvar);
  return 0;
}
