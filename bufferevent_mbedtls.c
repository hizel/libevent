/*
 * Copyright (c) 2009-2012 Niels Provos and Nick Mathewson
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// Get rid of OSX 10.7 and greater deprecation warnings.
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#include "event2/event-config.h"
#include "evconfig-private.h"

#include <sys/types.h>

#ifdef EVENT__HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef EVENT__HAVE_STDARG_H
#include <stdarg.h>
#endif
#ifdef EVENT__HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef _WIN32
#include <winsock2.h>
#endif

#include "event2/bufferevent.h"
#include "event2/bufferevent_struct.h"
#include "event2/bufferevent_ssl.h"
#include "event2/buffer.h"
#include "event2/event.h"

#include "mm-internal.h"
#include "bufferevent-internal.h"
#include "log-internal.h"



//#include <mbedtls/ssl.h>
#include <mbedtls/net.h>


#if 0
static void
print_err(int val)
{
	int err;
	printf("Error was %d\n", val);

	while ((err = ERR_get_error())) {
		const char *msg = (const char*)ERR_reason_error_string(err);
		const char *lib = (const char*)ERR_lib_error_string(err);
		const char *func = (const char*)ERR_func_error_string(err);

		printf("%s in %s %s\n", msg, lib, func);
	}
}
#else
#define print_err(v) ((void)0)
#endif


struct bio_data_counts {
  unsigned long n_written;
  unsigned long n_read;
};

struct bufferevent_mbedtls {
  /* Shared fields with common bufferevent implementation code.
     If we were set up with an underlying bufferevent, we use the
     events here as timers only.  If we have an SSL, then we use
     the events as socket events.
   */
  struct bufferevent_private bev;
  /* An underlying bufferevent that we're directing our output to.
     If it's NULL, then we're connected to an fd, not an evbuffer. */
  struct bufferevent *underlying;
  /* The SSL object doing our encryption. */
  struct mbedtls_ssl_context *ssl;

  int fd;

  /* A callback that's invoked when data arrives on our outbuf so we
     know to write data to the SSL. */
  struct evbuffer_cb_entry *outbuf_cb;

  /* A count of how much data the bios have read/written total.  Used
     for rate-limiting. */
  struct bio_data_counts counts;

  /* If this value is greater than 0, then the last SSL_write blocked,
   * and we need to try it again with this many bytes. */
  ev_ssize_t last_write;

  /* When we next get available space, we should say "read" instead of
     "write". This can happen if there's a renegotiation during a read
     operation. */
  unsigned read_blocked_on_write : 1;
  /* When we next get data, we should say "write" instead of "read". */
  unsigned write_blocked_on_read : 1;
  /* Treat TCP close before SSL close on SSL >= v3 as clean EOF. */
  unsigned allow_dirty_shutdown : 1;

  long error;

  /* Are we currently connecting, accepting, or doing IO? */
  unsigned state : 2;
};

static int be_openssl_enable(struct bufferevent *, short);
static int be_openssl_disable(struct bufferevent *, short);
static void be_openssl_unlink(struct bufferevent *);
static void be_openssl_destruct(struct bufferevent *);
static int be_openssl_adj_timeouts(struct bufferevent *);
static int be_openssl_flush(struct bufferevent *bufev,
                            short iotype, enum bufferevent_flush_mode mode);
static int be_openssl_ctrl(struct bufferevent *, enum bufferevent_ctrl_op, union bufferevent_ctrl_data *);

const struct bufferevent_ops bufferevent_ops_mbedtls = {
  "ssl",
  evutil_offsetof(struct bufferevent_mbedtls, bev.bev),
  be_openssl_enable,
  be_openssl_disable,
  be_openssl_unlink,
  be_openssl_destruct,
  be_openssl_adj_timeouts,
  be_openssl_flush,
  be_openssl_ctrl,
};

/* Given a bufferevent, return a pointer to the bufferevent_openssl that
 * contains it, if any. */
static inline struct bufferevent_mbedtls *
upcast(struct bufferevent *bev)
{
  struct bufferevent_mbedtls *bev_o;
  if (bev->be_ops != &bufferevent_ops_mbedtls)
    return NULL;
  bev_o = (void*)( ((char*)bev) -
                   evutil_offsetof(struct bufferevent_mbedtls, bev.bev));
  EVUTIL_ASSERT(bev_o->bev.bev.be_ops == &bufferevent_ops_mbedtls);
  return bev_o;
}

/* Have the base communications channel (either the underlying bufferevent or
 * ev_read and ev_write) start reading.  Take the read-blocked-on-write flag
 * into account. */
static int
start_reading(struct bufferevent_mbedtls *bev_ssl)
{
  if (bev_ssl->underlying) {
    bufferevent_unsuspend_read_(bev_ssl->underlying,
                                BEV_SUSPEND_FILT_READ);
    return 0;
  } else {
    struct bufferevent *bev = &bev_ssl->bev.bev;
    int r;
    r = bufferevent_add_event_(&bev->ev_read, &bev->timeout_read);
    if (r == 0 && bev_ssl->read_blocked_on_write)
      r = bufferevent_add_event_(&bev->ev_write,
                                 &bev->timeout_write);
    return r;
  }
}

/* Have the base communications channel (either the underlying bufferevent or
 * ev_read and ev_write) start writing.  Take the write-blocked-on-read flag
 * into account. */
static int
start_writing(struct bufferevent_mbedtls *bev_ssl)
{
  int r = 0;
  if (bev_ssl->underlying) {
    ;
  } else {
    struct bufferevent *bev = &bev_ssl->bev.bev;
    r = bufferevent_add_event_(&bev->ev_write, &bev->timeout_write);
    if (!r && bev_ssl->write_blocked_on_read)
      r = bufferevent_add_event_(&bev->ev_read,
                                 &bev->timeout_read);
  }
  return r;
}

static void
stop_reading(struct bufferevent_mbedtls *bev_ssl)
{
  if (bev_ssl->write_blocked_on_read)
    return;
  if (bev_ssl->underlying) {
    bufferevent_suspend_read_(bev_ssl->underlying,
                              BEV_SUSPEND_FILT_READ);
  } else {
    struct bufferevent *bev = &bev_ssl->bev.bev;
    event_del(&bev->ev_read);
  }
}

static void
stop_writing(struct bufferevent_mbedtls *bev_ssl)
{
  if (bev_ssl->read_blocked_on_write)
    return;
  if (bev_ssl->underlying) {
    ;
  } else {
    struct bufferevent *bev = &bev_ssl->bev.bev;
    event_del(&bev->ev_write);
  }
}

static int
set_rbow(struct bufferevent_mbedtls *bev_ssl)
{
  if (!bev_ssl->underlying)
    stop_reading(bev_ssl);
  bev_ssl->read_blocked_on_write = 1;
  return start_writing(bev_ssl);
}

static int
set_wbor(struct bufferevent_mbedtls *bev_ssl)
{
  if (!bev_ssl->underlying)
    stop_writing(bev_ssl);
  bev_ssl->write_blocked_on_read = 1;
  return start_reading(bev_ssl);
}

static int
clear_rbow(struct bufferevent_mbedtls *bev_ssl)
{
  struct bufferevent *bev = &bev_ssl->bev.bev;
  int r = 0;
  bev_ssl->read_blocked_on_write = 0;
  if (!(bev->enabled & EV_WRITE))
    stop_writing(bev_ssl);
  if (bev->enabled & EV_READ)
    r = start_reading(bev_ssl);
  return r;
}


static int
clear_wbor(struct bufferevent_mbedtls *bev_ssl)
{
  struct bufferevent *bev = &bev_ssl->bev.bev;
  int r = 0;
  bev_ssl->write_blocked_on_read = 0;
  if (!(bev->enabled & EV_READ))
    stop_reading(bev_ssl);
  if (bev->enabled & EV_WRITE)
    r = start_writing(bev_ssl);
  return r;
}

static void
conn_closed(struct bufferevent_mbedtls *bev_ssl, int when, int errcode, int ret)
{
  int event = BEV_EVENT_ERROR;

  switch (errcode) {
    case MBEDTLS_ERR_SSL_CONN_EOF:
      /* Possibly a clean shutdown. */
      event = BEV_EVENT_EOF;
      break;
    default:
      /* should be impossible; treat as normal error. */
      //event_warnx("BUG: Unexpected OpenSSL error code %d", errcode);
      break;
  }

  bev_ssl->error = errcode;

  stop_reading(bev_ssl);
  stop_writing(bev_ssl);

  /* when is BEV_EVENT_{READING|WRITING} */
  event = when | event;
  bufferevent_run_eventcb_(&bev_ssl->bev.bev, event, 0);
}

static void
init_bio_counts(struct bufferevent_mbedtls *bev_ssl)
{

/* TODO counts
  bev_ssl->counts.n_written =
    BIO_number_written(SSL_get_wbio(bev_ssl->ssl));
  bev_ssl->counts.n_read =
    BIO_number_read(SSL_get_rbio(bev_ssl->ssl));*/
}

static inline void
decrement_buckets(struct bufferevent_mbedtls *bev_ssl)
{
  /* TODO counts
  unsigned long num_w = BIO_number_written(SSL_get_wbio(bev_ssl->ssl));
  unsigned long num_r = BIO_number_read(SSL_get_rbio(bev_ssl->ssl));*/
  unsigned long num_w = 0;
  unsigned long num_r = 0;
  /* These next two subtractions can wrap around. That's okay. */
  unsigned long w = num_w - bev_ssl->counts.n_written;
  unsigned long r = num_r - bev_ssl->counts.n_read;
  if (w)
    bufferevent_decrement_write_buckets_(&bev_ssl->bev, w);
  if (r)
    bufferevent_decrement_read_buckets_(&bev_ssl->bev, r);
  bev_ssl->counts.n_written = num_w;
  bev_ssl->counts.n_read = num_r;
}

#define OP_MADE_PROGRESS 1
#define OP_BLOCKED 2
#define OP_ERR 4

/* Return a bitmask of OP_MADE_PROGRESS (if we read anything); OP_BLOCKED (if
   we're now blocked); and OP_ERR (if an error occurred). */
static int
do_read(struct bufferevent_mbedtls *bev_ssl, int n_to_read) {
  /* Requires lock */
  struct bufferevent *bev = &bev_ssl->bev.bev;
  struct evbuffer *input = bev->input;
  int r, n, i, n_used = 0, atmost;
  struct evbuffer_iovec space[2];
  int result = 0;

  if (bev_ssl->bev.read_suspended)
    return 0;

  atmost = bufferevent_get_read_max_(&bev_ssl->bev);
  if (n_to_read > atmost)
    n_to_read = atmost;

  n = evbuffer_reserve_space(input, n_to_read, space, 2);
  if (n < 0)
    return OP_ERR;

  for (i=0; i<n; ++i) {
    if (bev_ssl->bev.read_suspended)
      break;
    //ERR_clear_error();
    r = mbedtls_ssl_read(bev_ssl->ssl, space[i].iov_base, space[i].iov_len);
    if (r>0) {
      result |= OP_MADE_PROGRESS;
      if (bev_ssl->read_blocked_on_write)
      if (clear_rbow(bev_ssl) < 0)
        return OP_ERR | result;
      ++n_used;
      space[i].iov_len = r;
      decrement_buckets(bev_ssl);
    } else {
      int err = bev_ssl->error;
      print_err(err);
      switch (err) {
        case MBEDTLS_ERR_SSL_WANT_READ:
          /* Can't read until underlying has more data. */
          if (bev_ssl->read_blocked_on_write)
          if (clear_rbow(bev_ssl) < 0)
            return OP_ERR | result;
          break;
        case MBEDTLS_ERR_SSL_WANT_WRITE:
          /* This read operation requires a write, and the
           * underlying is full */
          if (!bev_ssl->read_blocked_on_write)
          if (set_rbow(bev_ssl) < 0)
            return OP_ERR | result;
          break;
        default:
          conn_closed(bev_ssl, BEV_EVENT_READING, err, r);
          break;
      }
      result |= OP_BLOCKED;
      break; /* out of the loop */
    }
  }

  if (n_used) {
    evbuffer_commit_space(input, space, n_used);
    if (bev_ssl->underlying)
      BEV_RESET_GENERIC_READ_TIMEOUT(bev);
  }

  return result;
}

/* Return a bitmask of OP_MADE_PROGRESS (if we wrote anything); OP_BLOCKED (if
   we're now blocked); and OP_ERR (if an error occurred). */
static int
do_write(struct bufferevent_mbedtls *bev_ssl, int atmost)
{
  int i, r, n, n_written = 0;
  struct bufferevent *bev = &bev_ssl->bev.bev;
  struct evbuffer *output = bev->output;
  struct evbuffer_iovec space[8];
  int result = 0;

  if (bev_ssl->last_write > 0)
    atmost = bev_ssl->last_write;
  else
    atmost = bufferevent_get_write_max_(&bev_ssl->bev);

  n = evbuffer_peek(output, atmost, NULL, space, 8);
  if (n < 0)
    return OP_ERR | result;

  if (n > 8)
    n = 8;
  for (i=0; i < n; ++i) {
    if (bev_ssl->bev.write_suspended)
      break;

    /* SSL_write will (reasonably) return 0 if we tell it to
       send 0 data.  Skip this case so we don't interpret the
       result as an error */
    if (space[i].iov_len == 0)
      continue;

    //ERR_clear_error();
    r = mbedtls_ssl_write(bev_ssl->ssl, space[i].iov_base,
                  space[i].iov_len);
    if (r > 0) {
      result |= OP_MADE_PROGRESS;
      if (bev_ssl->write_blocked_on_read)
      if (clear_wbor(bev_ssl) < 0)
        return OP_ERR | result;
      n_written += r;
      bev_ssl->last_write = -1;
      decrement_buckets(bev_ssl);
    } else {
      int err = bev_ssl->error;
      print_err(err);
      switch (err) {
        case MBEDTLS_ERR_SSL_WANT_WRITE:
          /* Can't read until underlying has more data. */
          if (bev_ssl->write_blocked_on_read)
          if (clear_wbor(bev_ssl) < 0)
            return OP_ERR | result;
          bev_ssl->last_write = space[i].iov_len;
          break;
        case MBEDTLS_ERR_SSL_WANT_READ:
          /* This read operation requires a write, and the
           * underlying is full */
          if (!bev_ssl->write_blocked_on_read)
          if (set_wbor(bev_ssl) < 0)
            return OP_ERR | result;
          bev_ssl->last_write = space[i].iov_len;
          break;
        default:
          conn_closed(bev_ssl, BEV_EVENT_WRITING, err, r);
          bev_ssl->last_write = -1;
          break;
      }
      result |= OP_BLOCKED;
      break;
    }
  }
  if (n_written) {
    evbuffer_drain(output, n_written);
    if (bev_ssl->underlying)
      BEV_RESET_GENERIC_WRITE_TIMEOUT(bev);

    bufferevent_trigger_nolock_(bev, EV_WRITE, 0);
  }
  return result;
}

#define WRITE_FRAME 15000

#define READ_DEFAULT 4096

/* Try to figure out how many bytes to read; return 0 if we shouldn't be
 * reading. */
static int
bytes_to_read(struct bufferevent_mbedtls *bev)
{
  struct evbuffer *input = bev->bev.bev.input;
  struct event_watermark *wm = &bev->bev.bev.wm_read;
  int result = READ_DEFAULT;
  ev_ssize_t limit;
  /* XXX 99% of this is generic code that nearly all bufferevents will
   * want. */

  if (bev->write_blocked_on_read) {
    return 0;
  }

  if (! (bev->bev.bev.enabled & EV_READ)) {
    return 0;
  }

  if (bev->bev.read_suspended) {
    return 0;
  }

  if (wm->high) {
    if (evbuffer_get_length(input) >= wm->high) {
      return 0;
    }

    result = wm->high - evbuffer_get_length(input);
  } else {
    result = READ_DEFAULT;
  }

  /* Respect the rate limit */
  limit = bufferevent_get_read_max_(&bev->bev);
  if (result > limit) {
    result = limit;
  }

  return result;
}


/* Things look readable.  If write is blocked on read, write till it isn't.
 * Read from the underlying buffer until we block or we hit our high-water
 * mark.
 */
static void
consider_reading(struct bufferevent_mbedtls *bev_ssl)
{
  int r;
  int n_to_read;
  int all_result_flags = 0;

  while (bev_ssl->write_blocked_on_read) {
    r = do_write(bev_ssl, WRITE_FRAME);
    if (r & (OP_BLOCKED|OP_ERR))
      break;
  }
  if (bev_ssl->write_blocked_on_read)
    return;

  n_to_read = bytes_to_read(bev_ssl);

  while (n_to_read) {
    r = do_read(bev_ssl, n_to_read);
    all_result_flags |= r;

    if (r & (OP_BLOCKED|OP_ERR))
      break;

    if (bev_ssl->bev.read_suspended)
      break;

    /* Read all pending data.  This won't hit the network
     * again, and will (most importantly) put us in a state
     * where we don't need to read anything else until the
     * socket is readable again.  It'll potentially make us
     * overrun our read high-watermark (somewhat
     * regrettable).  The damage to the rate-limit has
     * already been done, since OpenSSL went and read a
     * whole SSL record anyway. */
    //n_to_read = mbedtls_ssl_get_bytes_avail(bev_ssl->ssl); // TODO test

    /* XXX This if statement is actually a bad bug, added to avoid
     * XXX a worse bug.
     *
     * The bad bug: It can potentially cause resource unfairness
     * by reading too much data from the underlying bufferevent;
     * it can potentially cause read looping if the underlying
     * bufferevent is a bufferevent_pair and deferred callbacks
     * aren't used.
     *
     * The worse bug: If we didn't do this, then we would
     * potentially not read any more from bev_ssl->underlying
     * until more data arrived there, which could lead to us
     * waiting forever.
     */
    if (bev_ssl->underlying)
      n_to_read = bytes_to_read(bev_ssl);
    else
      break;
  }

  if (all_result_flags & OP_MADE_PROGRESS) {
    struct bufferevent *bev = &bev_ssl->bev.bev;

    bufferevent_trigger_nolock_(bev, EV_READ, 0);
  }

  if (!bev_ssl->underlying) {
    /* Should be redundant, but let's avoid busy-looping */
    if (bev_ssl->bev.read_suspended ||
        !(bev_ssl->bev.bev.enabled & EV_READ)) {
      event_del(&bev_ssl->bev.bev.ev_read);
    }
  }
}

static void
consider_writing(struct bufferevent_mbedtls *bev_ssl)
{
  int r;
  struct evbuffer *output = bev_ssl->bev.bev.output;
  struct evbuffer *target = NULL;
  struct event_watermark *wm = NULL;

  while (bev_ssl->read_blocked_on_write) {
    r = do_read(bev_ssl, 1024); /* XXXX 1024 is a hack */
    if (r & OP_MADE_PROGRESS) {
      struct bufferevent *bev = &bev_ssl->bev.bev;

      bufferevent_trigger_nolock_(bev, EV_READ, 0);
    }
    if (r & (OP_ERR|OP_BLOCKED))
      break;
  }
  if (bev_ssl->read_blocked_on_write)
    return;
  if (bev_ssl->underlying) {
    target = bev_ssl->underlying->output;
    wm = &bev_ssl->underlying->wm_write;
  }
  while ((bev_ssl->bev.bev.enabled & EV_WRITE) &&
         (! bev_ssl->bev.write_suspended) &&
         evbuffer_get_length(output) &&
         (!target || (! wm->high || evbuffer_get_length(target) < wm->high))) {
    int n_to_write;
    if (wm && wm->high)
      n_to_write = wm->high - evbuffer_get_length(target);
    else
      n_to_write = WRITE_FRAME;
    r = do_write(bev_ssl, n_to_write);
    if (r & (OP_BLOCKED|OP_ERR))
      break;
  }

  if (!bev_ssl->underlying) {
    if (evbuffer_get_length(output) == 0) {
      event_del(&bev_ssl->bev.bev.ev_write);
    } else if (bev_ssl->bev.write_suspended ||
               !(bev_ssl->bev.bev.enabled & EV_WRITE)) {
      /* Should be redundant, but let's avoid busy-looping */
      event_del(&bev_ssl->bev.bev.ev_write);
    }
  }
}

static void
be_openssl_readcb(struct bufferevent *bev_base, void *ctx)
{
  struct bufferevent_mbedtls *bev_ssl = ctx;
  consider_reading(bev_ssl);
}

static void
be_openssl_writecb(struct bufferevent *bev_base, void *ctx)
{
  struct bufferevent_mbedtls *bev_ssl = ctx;
  consider_writing(bev_ssl);
}

static void
be_openssl_eventcb(struct bufferevent *bev_base, short what, void *ctx)
{
  struct bufferevent_mbedtls *bev_ssl = ctx;
  int event = 0;

  if (what & BEV_EVENT_EOF) {
    if (bev_ssl->allow_dirty_shutdown)
      event = BEV_EVENT_EOF;
    else
      event = BEV_EVENT_ERROR;
  } else if (what & BEV_EVENT_TIMEOUT) {
    /* We sure didn't set this.  Propagate it to the user. */
    event = what;
  } else if (what & BEV_EVENT_ERROR) {
    /* An error occurred on the connection.  Propagate it to the user. */
    event = what;
  } else if (what & BEV_EVENT_CONNECTED) {
    /* Ignore it.  We're saying SSL_connect() already, which will
       eat it. */
  }
  if (event)
    bufferevent_run_eventcb_(&bev_ssl->bev.bev, event, 0);
}

static void
be_openssl_readeventcb(evutil_socket_t fd, short what, void *ptr)
{
  struct bufferevent_mbedtls *bev_ssl = ptr;
  bufferevent_incref_and_lock_(&bev_ssl->bev.bev);
  if (what == EV_TIMEOUT) {
    bufferevent_run_eventcb_(&bev_ssl->bev.bev,
                             BEV_EVENT_TIMEOUT|BEV_EVENT_READING, 0);
  } else {
    consider_reading(bev_ssl);
  }
  bufferevent_decref_and_unlock_(&bev_ssl->bev.bev);
}

static void
be_openssl_writeeventcb(evutil_socket_t fd, short what, void *ptr)
{
  struct bufferevent_mbedtls *bev_ssl = ptr;
  bufferevent_incref_and_lock_(&bev_ssl->bev.bev);
  if (what == EV_TIMEOUT) {
    bufferevent_run_eventcb_(&bev_ssl->bev.bev,
                             BEV_EVENT_TIMEOUT|BEV_EVENT_WRITING, 0);
  } else {
    consider_writing(bev_ssl);
  }
  bufferevent_decref_and_unlock_(&bev_ssl->bev.bev);
}

static int
be_openssl_auto_fd(struct bufferevent_mbedtls *bev_ssl, int fd)
{
  if (!bev_ssl->underlying) {
    struct bufferevent *bev = &bev_ssl->bev.bev;
    if (event_initialized(&bev->ev_read) && fd < 0) {
      fd = event_get_fd(&bev->ev_read);
    }
  }
  return fd;
}

static int
set_open_callbacks(struct bufferevent_mbedtls *bev_ssl, evutil_socket_t fd)
{
  if (bev_ssl->underlying) {
    bufferevent_setcb(bev_ssl->underlying,
                      be_openssl_readcb, be_openssl_writecb, be_openssl_eventcb,
                      bev_ssl);
    return 0;
  } else {
    struct bufferevent *bev = &bev_ssl->bev.bev;
    int rpending=0, wpending=0, r1=0, r2=0;

    if (event_initialized(&bev->ev_read)) {
      rpending = event_pending(&bev->ev_read, EV_READ, NULL);
      wpending = event_pending(&bev->ev_write, EV_WRITE, NULL);

      event_del(&bev->ev_read);
      event_del(&bev->ev_write);
    }

    event_assign(&bev->ev_read, bev->ev_base, fd,
                 EV_READ|EV_PERSIST|EV_FINALIZE,
                 be_openssl_readeventcb, bev_ssl);
    event_assign(&bev->ev_write, bev->ev_base, fd,
                 EV_WRITE|EV_PERSIST|EV_FINALIZE,
                 be_openssl_writeeventcb, bev_ssl);

    if (rpending)
      r1 = bufferevent_add_event_(&bev->ev_read, &bev->timeout_read);
    if (wpending)
      r2 = bufferevent_add_event_(&bev->ev_write, &bev->timeout_write);

    return (r1<0 || r2<0) ? -1 : 0;
  }
}
static int
set_open_callbacks_auto(struct bufferevent_mbedtls *bev_ssl, evutil_socket_t fd)
{
  fd = be_openssl_auto_fd(bev_ssl, fd);
  return set_open_callbacks(bev_ssl, fd);
}

static int
do_handshake(struct bufferevent_mbedtls *bev_ssl)
{
  int r;

  switch (bev_ssl->state) {
    default:
    case BUFFEREVENT_SSL_OPEN:
      EVUTIL_ASSERT(0);
      return -1;
    case BUFFEREVENT_SSL_CONNECTING:
    case BUFFEREVENT_SSL_ACCEPTING:
      //ERR_clear_error();
      r = mbedtls_ssl_handshake(bev_ssl->ssl);
      break;
  }
  decrement_buckets(bev_ssl);

  if (r==0) {
    int fd = event_get_fd(&bev_ssl->bev.bev.ev_read);
    /* We're done! */
    bev_ssl->state = BUFFEREVENT_SSL_OPEN;
    set_open_callbacks(bev_ssl, fd); /* XXXX handle failure */
    /* Call do_read and do_write as needed */
    bufferevent_enable(&bev_ssl->bev.bev, bev_ssl->bev.bev.enabled);
    bufferevent_run_eventcb_(&bev_ssl->bev.bev,
                             BEV_EVENT_CONNECTED, 0);
    return 1;
  } else {
    int err = r;
    print_err(err);
    switch (err) {
      case MBEDTLS_ERR_SSL_WANT_WRITE:
        if (!bev_ssl->underlying) {
          stop_reading(bev_ssl);
          return start_writing(bev_ssl);
        }
        return 0;
      case MBEDTLS_ERR_SSL_WANT_READ:
        if (!bev_ssl->underlying) {
          stop_writing(bev_ssl);
          return start_reading(bev_ssl);
        }
        return 0;
      default:
        conn_closed(bev_ssl, BEV_EVENT_READING, err, r);
        return -1;
    }
  }
}

static void
be_openssl_handshakecb(struct bufferevent *bev_base, void *ctx)
{
  struct bufferevent_mbedtls *bev_ssl = ctx;
  do_handshake(bev_ssl);/* XXX handle failure */
}

static void
be_openssl_handshakeeventcb(evutil_socket_t fd, short what, void *ptr)
{
  struct bufferevent_mbedtls *bev_ssl = ptr;

  bufferevent_incref_and_lock_(&bev_ssl->bev.bev);
  if (what & EV_TIMEOUT) {
    bufferevent_run_eventcb_(&bev_ssl->bev.bev, BEV_EVENT_TIMEOUT, 0);
  } else
    do_handshake(bev_ssl);/* XXX handle failure */
  bufferevent_decref_and_unlock_(&bev_ssl->bev.bev);
}

static int
set_handshake_callbacks(struct bufferevent_mbedtls *bev_ssl, evutil_socket_t fd)
{
  if (bev_ssl->underlying) {
    bufferevent_setcb(bev_ssl->underlying,
                      be_openssl_handshakecb, be_openssl_handshakecb,
                      be_openssl_eventcb,
                      bev_ssl);
    return do_handshake(bev_ssl);
  } else {
    struct bufferevent *bev = &bev_ssl->bev.bev;

    if (event_initialized(&bev->ev_read)) {
      event_del(&bev->ev_read);
      event_del(&bev->ev_write);
    }

    event_assign(&bev->ev_read, bev->ev_base, fd,
                 EV_READ|EV_PERSIST|EV_FINALIZE,
                 be_openssl_handshakeeventcb, bev_ssl);
    event_assign(&bev->ev_write, bev->ev_base, fd,
                 EV_WRITE|EV_PERSIST|EV_FINALIZE,
                 be_openssl_handshakeeventcb, bev_ssl);
    if (fd >= 0)
      bufferevent_enable(bev, bev->enabled);
    return 0;
  }
}

static int
set_handshake_callbacks_auto(struct bufferevent_mbedtls *bev_ssl, evutil_socket_t fd)
{
  fd = be_openssl_auto_fd(bev_ssl, fd);
  return set_handshake_callbacks(bev_ssl, fd);
}

int
bufferevent_ssl_renegotiate(struct bufferevent *bev)
{
  struct bufferevent_mbedtls *bev_ssl = upcast(bev);
  if (!bev_ssl)
    return -1;
  //if (SSL_renegotiate(bev_ssl->ssl) < 0)
  //  return -1;
  bev_ssl->state = BUFFEREVENT_SSL_CONNECTING;
  if (set_handshake_callbacks_auto(bev_ssl, -1) < 0)
    return -1;
  if (!bev_ssl->underlying)
    return do_handshake(bev_ssl);
  return 0;
}

static void
be_openssl_outbuf_cb(struct evbuffer *buf,
                     const struct evbuffer_cb_info *cbinfo, void *arg)
{
  struct bufferevent_mbedtls *bev_ssl = arg;
  int r = 0;
  /* XXX need to hold a reference here. */

  if (cbinfo->n_added && bev_ssl->state == BUFFEREVENT_SSL_OPEN &&
      cbinfo->orig_size == 0) {
    r = bufferevent_add_event_(&bev_ssl->bev.bev.ev_write,
                               &bev_ssl->bev.bev.timeout_write);
  }
  /* XXX Handle r < 0 */
  (void)r;
}


static int
be_openssl_enable(struct bufferevent *bev, short events)
{
  struct bufferevent_mbedtls *bev_ssl = upcast(bev);
  int r1 = 0, r2 = 0;

  if (events & EV_READ)
    r1 = start_reading(bev_ssl);
  if (events & EV_WRITE)
    r2 = start_writing(bev_ssl);

  if (bev_ssl->underlying) {
    if (events & EV_READ)
      BEV_RESET_GENERIC_READ_TIMEOUT(bev);
    if (events & EV_WRITE)
      BEV_RESET_GENERIC_WRITE_TIMEOUT(bev);

    if (events & EV_READ)
      consider_reading(bev_ssl);
    if (events & EV_WRITE)
      consider_writing(bev_ssl);
  }
  return (r1 < 0 || r2 < 0) ? -1 : 0;
}

static int
be_openssl_disable(struct bufferevent *bev, short events)
{
  struct bufferevent_mbedtls *bev_ssl = upcast(bev);

  if (events & EV_READ)
    stop_reading(bev_ssl);
  if (events & EV_WRITE)
    stop_writing(bev_ssl);

  if (bev_ssl->underlying) {
    if (events & EV_READ)
      BEV_DEL_GENERIC_READ_TIMEOUT(bev);
    if (events & EV_WRITE)
      BEV_DEL_GENERIC_WRITE_TIMEOUT(bev);
  }
  return 0;
}

static void
be_openssl_unlink(struct bufferevent *bev)
{
  struct bufferevent_mbedtls *bev_ssl = upcast(bev);

  if (bev_ssl->bev.options & BEV_OPT_CLOSE_ON_FREE) {
    if (bev_ssl->underlying) {
      if (BEV_UPCAST(bev_ssl->underlying)->refcnt < 2) {
        event_warnx("BEV_OPT_CLOSE_ON_FREE set on an "
                      "bufferevent with too few references");
      } else {
        bufferevent_free(bev_ssl->underlying);
        /* We still have a reference to it, via our
         * BIO. So we don't drop this. */
        // bev_ssl->underlying = NULL;
      }
    }
  } else {
    if (bev_ssl->underlying) {
      if (bev_ssl->underlying->errorcb == be_openssl_eventcb)
        bufferevent_setcb(bev_ssl->underlying,
                          NULL,NULL,NULL,NULL);
      bufferevent_unsuspend_read_(bev_ssl->underlying,
                                  BEV_SUSPEND_FILT_READ);
    }
  }
}

static void
be_openssl_destruct(struct bufferevent *bev)
{
  struct bufferevent_mbedtls *bev_ssl = upcast(bev);

  if (bev_ssl->bev.options & BEV_OPT_CLOSE_ON_FREE) {
    if (! bev_ssl->underlying) {
      evutil_socket_t fd = -1;
      if (fd >= 0)
        evutil_closesocket(fd);
    }
    mbedtls_ssl_free(bev_ssl->ssl);
  }
}

static int
be_openssl_adj_timeouts(struct bufferevent *bev)
{
  struct bufferevent_mbedtls *bev_ssl = upcast(bev);

  if (bev_ssl->underlying) {
    return bufferevent_generic_adj_timeouts_(bev);
  } else {
    return bufferevent_generic_adj_existing_timeouts_(bev);
  }
}

static int
be_openssl_flush(struct bufferevent *bufev,
                 short iotype, enum bufferevent_flush_mode mode)
{
  /* XXXX Implement this. */
  return 0;
}

static int
be_openssl_ctrl(struct bufferevent *bev,
                enum bufferevent_ctrl_op op, union bufferevent_ctrl_data *data)
{
  struct bufferevent_mbedtls *bev_ssl = upcast(bev);
  switch (op) {
    case BEV_CTRL_SET_FD:
      if (bev_ssl->underlying)
        return -1;

      bev_ssl->fd = data->fd;
      mbedtls_ssl_set_bio(bev_ssl->ssl, &bev_ssl->fd, mbedtls_net_send, mbedtls_net_recv, NULL);

      if (bev_ssl->state == BUFFEREVENT_SSL_OPEN && data->fd >= 0)
        return set_open_callbacks(bev_ssl, data->fd);
      else {
        return set_handshake_callbacks(bev_ssl, data->fd);
      }
    case BEV_CTRL_GET_FD:
      data->fd = event_get_fd(&bev->ev_read);
      return 0;
    case BEV_CTRL_GET_UNDERLYING:
      data->ptr = bev_ssl->underlying;
      return 0;
    case BEV_CTRL_CANCEL_ALL:
    default:
      return -1;
  }
}

struct mbedtls_ssl_context *
bufferevent_openssl_get_ssl(struct bufferevent *bufev)
{
  struct bufferevent_mbedtls *bev_ssl = upcast(bufev);
  if (!bev_ssl)
    return NULL;
  return bev_ssl->ssl;
}

static struct bufferevent *
bufferevent_openssl_new_impl(struct event_base *base,
                             struct bufferevent *underlying,
                             evutil_socket_t fd,
                             struct mbedtls_ssl_context *ssl,
                             enum bufferevent_ssl_state state,
                             int options)
{
  struct bufferevent_mbedtls *bev_ssl = NULL;
  struct bufferevent_private *bev_p = NULL;
  int tmp_options = options & ~BEV_OPT_THREADSAFE;

  if (underlying != NULL && fd >= 0)
    return NULL; /* Only one can be set. */

  if (!(bev_ssl = mm_calloc(1, sizeof(struct bufferevent_mbedtls))))
    goto err;

  bev_p = &bev_ssl->bev;

  if (bufferevent_init_common_(bev_p, base,
                               &bufferevent_ops_mbedtls, tmp_options) < 0)
    goto err;

  bev_ssl->underlying = underlying;
  bev_ssl->ssl = ssl;
  bev_ssl->fd = fd;

  mbedtls_ssl_set_bio(bev_ssl->ssl, &bev_ssl->fd, mbedtls_net_send, mbedtls_net_recv, NULL);

  bev_ssl->outbuf_cb = evbuffer_add_cb(bev_p->bev.output,
                                       be_openssl_outbuf_cb, bev_ssl);

  if (options & BEV_OPT_THREADSAFE)
    bufferevent_enable_locking_(&bev_ssl->bev.bev, NULL);

  if (underlying) {
    bufferevent_init_generic_timeout_cbs_(&bev_ssl->bev.bev);
    bufferevent_incref_(underlying);
  }

  bev_ssl->state = state;
  bev_ssl->last_write = -1;

  init_bio_counts(bev_ssl);

  switch (state) {
    case BUFFEREVENT_SSL_ACCEPTING:
      //mbedtls already setup
      //SSL_set_accept_state(bev_ssl->ssl);
      if (set_handshake_callbacks_auto(bev_ssl, fd) < 0)
        goto err;
      break;
    case BUFFEREVENT_SSL_CONNECTING:
      //mbedtls already setup
      //SSL_set_connect_state(bev_ssl->ssl);
      if (set_handshake_callbacks_auto(bev_ssl, fd) < 0)
        goto err;
      break;
    case BUFFEREVENT_SSL_OPEN:
      if (set_open_callbacks_auto(bev_ssl, fd) < 0)
        goto err;
      break;
    default:
      goto err;
  }

  if (underlying) {
    bufferevent_setwatermark(underlying, EV_READ, 0, 0);
    bufferevent_enable(underlying, EV_READ|EV_WRITE);
    if (state == BUFFEREVENT_SSL_OPEN)
      bufferevent_suspend_read_(underlying,
                                BEV_SUSPEND_FILT_READ);
  }

  return &bev_ssl->bev.bev;
  err:
  if (bev_ssl)
    bufferevent_free(&bev_ssl->bev.bev);
  return NULL;
}

struct bufferevent *
bufferevent_mbedtls_filter_new(struct event_base *base,
                               struct bufferevent *underlying,
                               struct mbedtls_ssl_context *ssl,
                               enum bufferevent_ssl_state state,
                               int options)
{
  /* We don't tell the BIO to close the bufferevent; we do it ourselves
   * on be_openssl_destruct */
  //int close_flag = 0; /* options & BEV_OPT_CLOSE_ON_FREE; */
  if (!underlying)
    return NULL;

  //mbedtls_ssl_set_bio(ssl->ssl, &ssl->fd, mbedtls_net_send, mbedtls_net_recv, NULL);

  return bufferevent_openssl_new_impl(
    base, underlying, -1, ssl, state, options);
}

struct bufferevent *
bufferevent_mbedtls_socket_new(struct event_base *base,
                               evutil_socket_t fd,
                               struct mbedtls_ssl_context *ssl,
                               enum bufferevent_ssl_state state,
                               int options)
{
  return bufferevent_openssl_new_impl(
    base, NULL, fd, ssl, state, options);
}

/*int
bufferevent_openssl_get_allow_dirty_shutdown(struct bufferevent *bev)
{
  int allow_dirty_shutdown = -1;
  struct bufferevent_mbedtls *bev_ssl;
  BEV_LOCK(bev);
  bev_ssl = upcast(bev);
  if (bev_ssl)
    allow_dirty_shutdown = bev_ssl->allow_dirty_shutdown;
  BEV_UNLOCK(bev);
  return allow_dirty_shutdown;
}

void
bufferevent_openssl_set_allow_dirty_shutdown(struct bufferevent *bev,
                                             int allow_dirty_shutdown)
{
  struct bufferevent_mbedtls *bev_ssl;
  BEV_LOCK(bev);
  bev_ssl = upcast(bev);
  if (bev_ssl)
    bev_ssl->allow_dirty_shutdown = !!allow_dirty_shutdown;
  BEV_UNLOCK(bev);
}*/


int
bufferevent_mbedtls_geterror(struct bufferevent *bev)
{
  long err = 0;
  struct bufferevent_mbedtls *bev_ssl;
  BEV_LOCK(bev);
  bev_ssl = upcast(bev);
  if (bev_ssl->error) {
    err = bev_ssl->error;
  }
  BEV_UNLOCK(bev);
  return err;
}
