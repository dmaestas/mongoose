/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 *
 * This software is dual-licensed: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. For the terms of this
 * license, see <http://www.gnu.org/licenses/>.
 *
 * You are free to use this software under the terms of the GNU General
 * Public License, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * Alternatively, you can license this software under a commercial
 * license, as set out in <https://www.cesanta.com/license>.
 */

#include "mongoose/src/internal.h"
#include "mongoose/src/util.h"
#include "mongoose/src/dns.h"
#include "mongoose/src/resolv.h"
#include "common/cs_time.h"

#define MG_MAX_HOST_LEN 200

#define MG_COPY_COMMON_CONNECTION_OPTIONS(dst, src) \
  memcpy(dst, src, sizeof(*dst));

/* Which flags can be pre-set by the user at connection creation time. */
#define _MG_ALLOWED_CONNECT_FLAGS_MASK                                   \
  (MG_F_USER_1 | MG_F_USER_2 | MG_F_USER_3 | MG_F_USER_4 | MG_F_USER_5 | \
   MG_F_USER_6 | MG_F_WEBSOCKET_NO_DEFRAG | MG_F_ENABLE_BROADCAST)
/* Which flags should be modifiable by user's callbacks. */
#define _MG_CALLBACK_MODIFIABLE_FLAGS_MASK                               \
  (MG_F_USER_1 | MG_F_USER_2 | MG_F_USER_3 | MG_F_USER_4 | MG_F_USER_5 | \
   MG_F_USER_6 | MG_F_WEBSOCKET_NO_DEFRAG | MG_F_SEND_AND_CLOSE |        \
   MG_F_CLOSE_IMMEDIATELY | MG_F_IS_WEBSOCKET | MG_F_DELETE_CHUNK)

#ifndef intptr_t
#define intptr_t long
#endif

extern void mg_ev_mgr_init(struct mg_mgr *mgr);
extern void mg_ev_mgr_free(struct mg_mgr *mgr);
extern void mg_ev_mgr_add_conn(struct mg_connection *nc);
extern void mg_ev_mgr_remove_conn(struct mg_connection *nc);

MG_INTERNAL void mg_add_conn(struct mg_mgr *mgr, struct mg_connection *c) {
  DBG(("%p %p", mgr, c));
  c->mgr = mgr;
  c->next = mgr->active_connections;
  mgr->active_connections = c;
  c->prev = NULL;
  if (c->next != NULL) c->next->prev = c;
  mg_ev_mgr_add_conn(c);
}

MG_INTERNAL void mg_remove_conn(struct mg_connection *conn) {
  if (conn->prev == NULL) conn->mgr->active_connections = conn->next;
  if (conn->prev) conn->prev->next = conn->next;
  if (conn->next) conn->next->prev = conn->prev;
  mg_ev_mgr_remove_conn(conn);
}

MG_INTERNAL void mg_call(struct mg_connection *nc,
                         mg_event_handler_t ev_handler, int ev, void *ev_data) {
  if (ev_handler == NULL) {
    /*
     * If protocol handler is specified, call it. Otherwise, call user-specified
     * event handler.
     */
    ev_handler = nc->proto_handler ? nc->proto_handler : nc->handler;
  }
  DBG(("%p %s ev=%d ev_data=%p flags=%lu rmbl=%d smbl=%d", nc,
       ev_handler == nc->handler ? "user" : "proto", ev, ev_data, nc->flags,
       (int) nc->recv_mbuf.len, (int) nc->send_mbuf.len));

#if !defined(NO_LIBC) && !defined(MG_DISABLE_HEXDUMP)
  /* LCOV_EXCL_START */
  if (nc->mgr->hexdump_file != NULL && ev != MG_EV_POLL &&
      ev != MG_EV_SEND /* handled separately */) {
    if (ev == MG_EV_RECV) {
      mg_hexdump_connection(nc, nc->mgr->hexdump_file, nc->recv_mbuf.buf,
                            *(int *) ev_data, ev);
    } else {
      mg_hexdump_connection(nc, nc->mgr->hexdump_file, NULL, 0, ev);
    }
  }
/* LCOV_EXCL_STOP */
#endif
  if (ev_handler != NULL) {
    unsigned long flags_before = nc->flags;
    size_t recv_mbuf_before = nc->recv_mbuf.len, recved;
    ev_handler(nc, ev, ev_data);
    recved = (recv_mbuf_before - nc->recv_mbuf.len);
    /* Prevent user handler from fiddling with system flags. */
    if (ev_handler == nc->handler && nc->flags != flags_before) {
      nc->flags = (flags_before & ~_MG_CALLBACK_MODIFIABLE_FLAGS_MASK) |
                  (nc->flags & _MG_CALLBACK_MODIFIABLE_FLAGS_MASK);
    }
    if (recved > 0 && !(nc->flags & MG_F_UDP)) {
      mg_if_recved(nc, recved);
    }
  }
  DBG(("%p after %s flags=%lu rmbl=%d smbl=%d", nc,
       ev_handler == nc->handler ? "user" : "proto", nc->flags,
       (int) nc->recv_mbuf.len, (int) nc->send_mbuf.len));
}

void mg_if_timer(struct mg_connection *c, double now) {
  if (c->ev_timer_time > 0 && now >= c->ev_timer_time) {
    double old_value = c->ev_timer_time;
    mg_call(c, NULL, MG_EV_TIMER, &now);
    /*
     * To prevent timer firing all the time, reset the timer after delivery.
     * However, in case user sets it to new value, do not reset.
     */
    if (c->ev_timer_time == old_value) {
      c->ev_timer_time = 0;
    }
  }
}

void mg_if_poll(struct mg_connection *nc, time_t now) {
  if (!(nc->flags & MG_F_SSL) || (nc->flags & MG_F_SSL_HANDSHAKE_DONE)) {
    mg_call(nc, NULL, MG_EV_POLL, &now);
  }
}

static void mg_destroy_conn(struct mg_connection *conn, int destroy_if) {
  if (destroy_if) mg_if_destroy_conn(conn);
  if (conn->proto_data != NULL && conn->proto_data_destructor != NULL) {
    conn->proto_data_destructor(conn->proto_data);
  }
#if defined(MG_ENABLE_SSL) && !defined(MG_SOCKET_SIMPLELINK)
  if (conn->ssl != NULL) SSL_free(conn->ssl);
  if (conn->ssl_ctx != NULL) SSL_CTX_free(conn->ssl_ctx);
#endif
  mbuf_free(&conn->recv_mbuf);
  mbuf_free(&conn->send_mbuf);

  memset(conn, 0, sizeof(*conn));
  MG_FREE(conn);
}

void mg_close_conn(struct mg_connection *conn) {
  DBG(("%p %lu %d", conn, conn->flags, conn->sock));
  mg_remove_conn(conn);
  mg_if_destroy_conn(conn);
  mg_call(conn, NULL, MG_EV_CLOSE, NULL);
  mg_destroy_conn(conn, 0 /* destroy_if */);
}

void mg_mgr_init(struct mg_mgr *m, void *user_data) {
  memset(m, 0, sizeof(*m));
#ifndef MG_DISABLE_SOCKETPAIR
  m->ctl[0] = m->ctl[1] = INVALID_SOCKET;
#endif
  m->user_data = user_data;

#ifdef _WIN32
  {
    WSADATA data;
    WSAStartup(MAKEWORD(2, 2), &data);
  }
#elif defined(__unix__)
  /* Ignore SIGPIPE signal, so if client cancels the request, it
   * won't kill the whole process. */
  signal(SIGPIPE, SIG_IGN);
#endif

#if defined(MG_ENABLE_SSL) && !defined(MG_SOCKET_SIMPLELINK)
  {
    static int init_done;
    if (!init_done) {
      SSL_library_init();
      init_done++;
    }
  }
#endif

  mg_ev_mgr_init(m);
  DBG(("=================================="));
  DBG(("init mgr=%p", m));
}

#ifdef MG_ENABLE_JAVASCRIPT
static enum v7_err mg_send_js(struct v7 *v7, v7_val_t *res) {
  v7_val_t arg0 = v7_arg(v7, 0);
  v7_val_t arg1 = v7_arg(v7, 1);
  struct mg_connection *c = (struct mg_connection *) v7_get_ptr(v7, arg0);
  size_t len = 0;

  if (v7_is_string(arg1)) {
    const char *data = v7_get_string(v7, &arg1, &len);
    mg_send(c, data, len);
  }

  *res = v7_mk_number(v7, len);

  return V7_OK;
}

enum v7_err mg_enable_javascript(struct mg_mgr *m, struct v7 *v7,
                                 const char *init_file_name) {
  v7_val_t v;
  m->v7 = v7;
  v7_set_method(v7, v7_get_global(v7), "mg_send", mg_send_js);
  return v7_exec_file(v7, init_file_name, &v);
}
#endif

void mg_mgr_free(struct mg_mgr *m) {
  struct mg_connection *conn, *tmp_conn;

  DBG(("%p", m));
  if (m == NULL) return;
  /* Do one last poll, see https://github.com/cesanta/mongoose/issues/286 */
  mg_mgr_poll(m, 0);

#ifndef MG_DISABLE_SOCKETPAIR
  if (m->ctl[0] != INVALID_SOCKET) closesocket(m->ctl[0]);
  if (m->ctl[1] != INVALID_SOCKET) closesocket(m->ctl[1]);
  m->ctl[0] = m->ctl[1] = INVALID_SOCKET;
#endif

  for (conn = m->active_connections; conn != NULL; conn = tmp_conn) {
    tmp_conn = conn->next;
    mg_close_conn(conn);
  }

  mg_ev_mgr_free(m);
}

int mg_vprintf(struct mg_connection *nc, const char *fmt, va_list ap) {
  char mem[MG_VPRINTF_BUFFER_SIZE], *buf = mem;
  int len;

  if ((len = mg_avprintf(&buf, sizeof(mem), fmt, ap)) > 0) {
    mg_send(nc, buf, len);
  }
  if (buf != mem && buf != NULL) {
    MG_FREE(buf); /* LCOV_EXCL_LINE */
  }               /* LCOV_EXCL_LINE */

  return len;
}

int mg_printf(struct mg_connection *conn, const char *fmt, ...) {
  int len;
  va_list ap;
  va_start(ap, fmt);
  len = mg_vprintf(conn, fmt, ap);
  va_end(ap);
  return len;
}

#ifndef MG_DISABLE_SYNC_RESOLVER
/* TODO(lsm): use non-blocking resolver */
static int mg_resolve2(const char *host, struct in_addr *ina) {
#ifdef MG_ENABLE_GETADDRINFO
  int rv = 0;
  struct addrinfo hints, *servinfo, *p;
  struct sockaddr_in *h = NULL;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  if ((rv = getaddrinfo(host, NULL, NULL, &servinfo)) != 0) {
    DBG(("getaddrinfo(%s) failed: %s", host, strerror(errno)));
    return 0;
  }
  for (p = servinfo; p != NULL; p = p->ai_next) {
    memcpy(&h, &p->ai_addr, sizeof(struct sockaddr_in *));
    memcpy(ina, &h->sin_addr, sizeof(ina));
  }
  freeaddrinfo(servinfo);
  return 1;
#else
  struct hostent *he;
  if ((he = gethostbyname(host)) == NULL) {
    DBG(("gethostbyname(%s) failed: %s", host, strerror(errno)));
  } else {
    memcpy(ina, he->h_addr_list[0], sizeof(*ina));
    return 1;
  }
  return 0;
#endif /* MG_ENABLE_GETADDRINFO */
}

int mg_resolve(const char *host, char *buf, size_t n) {
  struct in_addr ad;
  return mg_resolve2(host, &ad) ? snprintf(buf, n, "%s", inet_ntoa(ad)) : 0;
}
#endif /* MG_DISABLE_SYNC_RESOLVER */

MG_INTERNAL struct mg_connection *mg_create_connection_base(
    struct mg_mgr *mgr, mg_event_handler_t callback,
    struct mg_add_sock_opts opts) {
  struct mg_connection *conn;

  if ((conn = (struct mg_connection *) MG_CALLOC(1, sizeof(*conn))) != NULL) {
    conn->sock = INVALID_SOCKET;
    conn->handler = callback;
    conn->mgr = mgr;
    conn->last_io_time = (time_t) mg_time();
    conn->flags = opts.flags & _MG_ALLOWED_CONNECT_FLAGS_MASK;
    conn->user_data = opts.user_data;
    /*
     * SIZE_MAX is defined as a long long constant in
     * system headers on some platforms and so it
     * doesn't compile with pedantic ansi flags.
     */
    conn->recv_mbuf_limit = ~0;
  } else {
    MG_SET_PTRPTR(opts.error_string, "failed to create connection");
  }

  return conn;
}

MG_INTERNAL struct mg_connection *mg_create_connection(
    struct mg_mgr *mgr, mg_event_handler_t callback,
    struct mg_add_sock_opts opts) {
  struct mg_connection *conn = mg_create_connection_base(mgr, callback, opts);

  if (!mg_if_create_conn(conn)) {
    MG_FREE(conn);
    conn = NULL;
    MG_SET_PTRPTR(opts.error_string, "failed to init connection");
  }

  return conn;
}

/*
 * Address format: [PROTO://][HOST]:PORT
 *
 * HOST could be IPv4/IPv6 address or a host name.
 * `host` is a destination buffer to hold parsed HOST part. Shoud be at least
 * MG_MAX_HOST_LEN bytes long.
 * `proto` is a returned socket type, either SOCK_STREAM or SOCK_DGRAM
 *
 * Return:
 *   -1   on parse error
 *    0   if HOST needs DNS lookup
 *   >0   length of the address string
 */
MG_INTERNAL int mg_parse_address(const char *str, union socket_address *sa,
                                 int *proto, char *host, size_t host_len) {
  unsigned int a, b, c, d, port = 0;
  int ch, len = 0;
#ifdef MG_ENABLE_IPV6
  char buf[100];
#endif

  /*
   * MacOS needs that. If we do not zero it, subsequent bind() will fail.
   * Also, all-zeroes in the socket address means binding to all addresses
   * for both IPv4 and IPv6 (INADDR_ANY and IN6ADDR_ANY_INIT).
   */
  memset(sa, 0, sizeof(*sa));
  sa->sin.sin_family = AF_INET;

  *proto = SOCK_STREAM;

  if (strncmp(str, "udp://", 6) == 0) {
    str += 6;
    *proto = SOCK_DGRAM;
  } else if (strncmp(str, "tcp://", 6) == 0) {
    str += 6;
  }

  if (sscanf(str, "%u.%u.%u.%u:%u%n", &a, &b, &c, &d, &port, &len) == 5) {
    /* Bind to a specific IPv4 address, e.g. 192.168.1.5:8080 */
    sa->sin.sin_addr.s_addr =
        htonl(((uint32_t) a << 24) | ((uint32_t) b << 16) | c << 8 | d);
    sa->sin.sin_port = htons((uint16_t) port);
#ifdef MG_ENABLE_IPV6
  } else if (sscanf(str, "[%99[^]]]:%u%n", buf, &port, &len) == 2 &&
             inet_pton(AF_INET6, buf, &sa->sin6.sin6_addr)) {
    /* IPv6 address, e.g. [3ffe:2a00:100:7031::1]:8080 */
    sa->sin6.sin6_family = AF_INET6;
    sa->sin.sin_port = htons((uint16_t) port);
#endif
#ifndef MG_DISABLE_RESOLVER
  } else if (strlen(str) < host_len &&
             sscanf(str, "%[^ :]:%u%n", host, &port, &len) == 2) {
    sa->sin.sin_port = htons((uint16_t) port);
    if (mg_resolve_from_hosts_file(host, sa) != 0) {
      return 0;
    }
#endif
  } else if (sscanf(str, ":%u%n", &port, &len) == 1 ||
             sscanf(str, "%u%n", &port, &len) == 1) {
    /* If only port is specified, bind to IPv4, INADDR_ANY */
    sa->sin.sin_port = htons((uint16_t) port);
  } else {
    return -1;
  }

  ch = str[len]; /* Character that follows the address */
  return port < 0xffffUL && (ch == '\0' || ch == ',' || isspace(ch)) ? len : -1;
}

#ifdef MG_ENABLE_SSL

#ifndef MG_SOCKET_SIMPLELINK
/*
 * Certificate generation script is at
 * https://github.com/cesanta/mongoose/blob/master/scripts/generate_ssl_certificates.sh
 */

#ifndef MG_DISABLE_PFS
/*
 * Cipher suite options used for TLS negotiation.
 * https://wiki.mozilla.org/Security/Server_Side_TLS#Recommended_configurations
 */
static const char mg_s_cipher_list[] =
#if defined(MG_SSL_CRYPTO_MODERN)
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:"
    "DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:"
    "ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:"
    "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:"
    "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:"
    "DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:"
    "DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:"
    "!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK"
#elif defined(MG_SSL_CRYPTO_OLD)
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:"
    "DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:"
    "ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:"
    "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:"
    "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:"
    "DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:"
    "DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:"
    "ECDHE-ECDSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:"
    "AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:DES-CBC3-SHA:"
    "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:"
    "!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA"
#else /* Default - intermediate. */
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:"
    "DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:"
    "ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:"
    "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:"
    "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:"
    "DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:"
    "DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:"
    "AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:"
    "DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:"
    "!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA"
#endif
    ;

/*
 * Default DH params for PFS cipher negotiation. This is a 2048-bit group.
 * Will be used if none are provided by the user in the certificate file.
 */
static const char mg_s_default_dh_params[] =
    "\
-----BEGIN DH PARAMETERS-----\n\
MIIBCAKCAQEAlvbgD/qh9znWIlGFcV0zdltD7rq8FeShIqIhkQ0C7hYFThrBvF2E\n\
Z9bmgaP+sfQwGpVlv9mtaWjvERbu6mEG7JTkgmVUJrUt/wiRzwTaCXBqZkdUO8Tq\n\
+E6VOEQAilstG90ikN1Tfo+K6+X68XkRUIlgawBTKuvKVwBhuvlqTGerOtnXWnrt\n\
ym//hd3cd5PBYGBix0i7oR4xdghvfR2WLVu0LgdThTBb6XP7gLd19cQ1JuBtAajZ\n\
wMuPn7qlUkEFDIkAZy59/Hue/H2Q2vU/JsvVhHWCQBL4F1ofEAt50il6ZxR1QfFK\n\
9VGKDC4oOgm9DlxwwBoC2FjqmvQlqVV3kwIBAg==\n\
-----END DH PARAMETERS-----\n";
#endif

static int mg_use_ca_cert(SSL_CTX *ctx, const char *cert) {
  if (ctx == NULL) {
    return -1;
  } else if (cert == NULL || strcmp(cert, "*") == 0) {
    return 0;
  }
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
  return SSL_CTX_load_verify_locations(ctx, cert, NULL) == 1 ? 0 : -2;
}

static int mg_use_cert(SSL_CTX *ctx, const char *cert, const char *key) {
  if (ctx == NULL) {
    return -1;
  } else if (cert == NULL || cert[0] == '\0' || key == NULL || key[0] == '\0') {
    return 0;
  } else if (SSL_CTX_use_certificate_file(ctx, cert, 1) == 0 ||
             SSL_CTX_use_PrivateKey_file(ctx, key, 1) == 0) {
    return -2;
  } else {
#ifndef MG_DISABLE_PFS
    BIO *bio = NULL;
    DH *dh = NULL;

    /* Try to read DH parameters from the cert/key file. */
    bio = BIO_new_file(cert, "r");
    if (bio != NULL) {
      dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
      BIO_free(bio);
    }
    /*
     * If there are no DH params in the file, fall back to hard-coded ones.
     * Not ideal, but better than nothing.
     */
    if (dh == NULL) {
      bio = BIO_new_mem_buf((void *) mg_s_default_dh_params, -1);
      dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
      BIO_free(bio);
    }
    if (dh != NULL) {
      SSL_CTX_set_tmp_dh(ctx, dh);
      SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
      DH_free(dh);
    }
#endif
    SSL_CTX_set_mode(ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_use_certificate_chain_file(ctx, cert);
    return 0;
  }
}

/*
 * Turn the connection into SSL mode.
 * `cert` is the certificate file in PEM format. For listening connections,
 * certificate file must contain private key and server certificate,
 * concatenated. It may also contain DH params - these will be used for more
 * secure key exchange. `ca_cert` is a certificate authority (CA) PEM file, and
 * it is optional (can be set to NULL). If `ca_cert` is non-NULL, then
 * the connection is so-called two-way-SSL: other peer's certificate is
 * checked against the `ca_cert`.
 *
 * Handy OpenSSL command to generate test self-signed certificate:
 *
 *    openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 999
 *
 * Return NULL on success, or error message on failure.
 */
static const char *mg_set_ssl2(struct mg_connection *nc, const char *cert,
                               const char *key, const char *ca_cert) {
  const char *result = NULL;
  DBG(("%p %s,%s,%s", nc, (cert ? cert : ""), (key ? key : ""),
       (ca_cert ? ca_cert : "")));

  if (nc->flags & MG_F_UDP) {
    return "SSL for UDP is not supported";
  }

  if (key == NULL && cert != NULL) key = cert;

  if (nc->ssl != NULL) {
    SSL_free(nc->ssl);
    nc->ssl = NULL;
  }
  if (nc->ssl_ctx != NULL) {
    SSL_CTX_free(nc->ssl_ctx);
    nc->ssl_ctx = NULL;
  }

  if ((nc->flags & MG_F_LISTENING) &&
      (nc->ssl_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
    result = "SSL_CTX_new() failed";
  } else if (!(nc->flags & MG_F_LISTENING) &&
             (nc->ssl_ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
    result = "SSL_CTX_new() failed";
  } else if (mg_use_cert(nc->ssl_ctx, cert, key) != 0) {
    result = "Invalid ssl cert";
  } else if (mg_use_ca_cert(nc->ssl_ctx, ca_cert) != 0) {
    result = "Invalid CA cert";
  } else if (!(nc->flags & MG_F_LISTENING) &&
             (nc->ssl = SSL_new(nc->ssl_ctx)) == NULL) {
    result = "SSL_new() failed";
  }

#ifndef MG_DISABLE_PFS
  SSL_CTX_set_cipher_list(nc->ssl_ctx, mg_s_cipher_list);
#endif

  if (result == NULL) nc->flags |= MG_F_SSL;

  return result;
}

const char *mg_set_ssl(struct mg_connection *nc, const char *cert,
                       const char *ca_cert) {
  return mg_set_ssl2(nc, cert, NULL, ca_cert);
}

#else
const char *mg_set_ssl2(struct mg_connection *nc, const char *cert,
                        const char *key, const char *ca_cert);
#endif /* MG_SOCKET_SIMPLELINK */

#endif /* MG_ENABLE_SSL */

struct mg_connection *mg_if_accept_new_conn(struct mg_connection *lc) {
  struct mg_add_sock_opts opts;
  struct mg_connection *nc;
  memset(&opts, 0, sizeof(opts));
  nc = mg_create_connection(lc->mgr, lc->handler, opts);
  if (nc == NULL) return NULL;
  nc->listener = lc;
  nc->proto_handler = lc->proto_handler;
  nc->user_data = lc->user_data;
  nc->recv_mbuf_limit = lc->recv_mbuf_limit;
  if (lc->flags & MG_F_SSL) nc->flags |= MG_F_SSL;
  mg_add_conn(nc->mgr, nc);
  DBG(("%p %p %d %d", lc, nc, nc->sock, (int) nc->flags));
  return nc;
}

void mg_if_accept_tcp_cb(struct mg_connection *nc, union socket_address *sa,
                         size_t sa_len) {
  (void) sa_len;
  nc->sa = *sa;
  mg_call(nc, NULL, MG_EV_ACCEPT, &nc->sa);
}

void mg_send(struct mg_connection *nc, const void *buf, int len) {
  nc->last_io_time = (time_t) mg_time();
  if (nc->flags & MG_F_UDP) {
    mg_if_udp_send(nc, buf, len);
  } else {
    mg_if_tcp_send(nc, buf, len);
  }
#if !defined(NO_LIBC) && !defined(MG_DISABLE_HEXDUMP)
  if (nc->mgr && nc->mgr->hexdump_file != NULL) {
    mg_hexdump_connection(nc, nc->mgr->hexdump_file, buf, len, MG_EV_SEND);
  }
#endif
}

void mg_if_sent_cb(struct mg_connection *nc, int num_sent) {
  if (num_sent < 0) {
    nc->flags |= MG_F_CLOSE_IMMEDIATELY;
  }
  mg_call(nc, NULL, MG_EV_SEND, &num_sent);
}

static void mg_recv_common(struct mg_connection *nc, void *buf, int len) {
  DBG(("%p %d %u", nc, len, (unsigned int) nc->recv_mbuf.len));
  if (nc->flags & MG_F_CLOSE_IMMEDIATELY) {
    DBG(("%p discarded %d bytes", nc, len));
    /*
     * This connection will not survive next poll. Do not deliver events,
     * send data to /dev/null without acking.
     */
    MG_FREE(buf);
    return;
  }
  nc->last_io_time = (time_t) mg_time();
  if (nc->recv_mbuf.len == 0) {
    /* Adopt buf as recv_mbuf's backing store. */
    mbuf_free(&nc->recv_mbuf);
    nc->recv_mbuf.buf = (char *) buf;
    nc->recv_mbuf.size = nc->recv_mbuf.len = len;
  } else {
    mbuf_append(&nc->recv_mbuf, buf, len);
    MG_FREE(buf);
  }
  mg_call(nc, NULL, MG_EV_RECV, &len);
}

void mg_if_recv_tcp_cb(struct mg_connection *nc, void *buf, int len) {
  mg_recv_common(nc, buf, len);
}

void mg_if_recv_udp_cb(struct mg_connection *nc, void *buf, int len,
                       union socket_address *sa, size_t sa_len) {
  assert(nc->flags & MG_F_UDP);
  DBG(("%p %u", nc, (unsigned int) len));
  if (nc->flags & MG_F_LISTENING) {
    struct mg_connection *lc = nc;
    /*
     * Do we have an existing connection for this source?
     * This is very inefficient for long connection lists.
     */
    for (nc = mg_next(lc->mgr, NULL); nc != NULL; nc = mg_next(lc->mgr, nc)) {
      if (memcmp(&nc->sa.sa, &sa->sa, sa_len) == 0 && nc->listener == lc) {
        break;
      }
    }
    if (nc == NULL) {
      struct mg_add_sock_opts opts;
      memset(&opts, 0, sizeof(opts));
      /* Create fake connection w/out sock initialization */
      nc = mg_create_connection_base(lc->mgr, lc->handler, opts);
      if (nc != NULL) {
        nc->sock = lc->sock;
        nc->listener = lc;
        nc->sa = *sa;
        nc->proto_handler = lc->proto_handler;
        nc->user_data = lc->user_data;
        nc->recv_mbuf_limit = lc->recv_mbuf_limit;
        nc->flags = MG_F_UDP;
        mg_add_conn(lc->mgr, nc);
        mg_call(nc, NULL, MG_EV_ACCEPT, &nc->sa);
      } else {
        DBG(("OOM"));
        /* No return here, we still need to drop on the floor */
      }
    }
  }
  if (nc != NULL) {
    mg_recv_common(nc, buf, len);
  } else {
    /* Drop on the floor. */
    MG_FREE(buf);
    mg_if_recved(nc, len);
  }
}

/*
 * Schedules an async connect for a resolved address and proto.
 * Called from two places: `mg_connect_opt()` and from async resolver.
 * When called from the async resolver, it must trigger `MG_EV_CONNECT` event
 * with a failure flag to indicate connection failure.
 */
MG_INTERNAL struct mg_connection *mg_do_connect(struct mg_connection *nc,
                                                int proto,
                                                union socket_address *sa) {
  DBG(("%p %s://%s:%hu", nc, proto == SOCK_DGRAM ? "udp" : "tcp",
       inet_ntoa(sa->sin.sin_addr), ntohs(sa->sin.sin_port)));

  nc->flags |= MG_F_CONNECTING;
  if (proto == SOCK_DGRAM) {
    mg_if_connect_udp(nc);
  } else {
    mg_if_connect_tcp(nc, sa);
  }
  mg_add_conn(nc->mgr, nc);
  return nc;
}

void mg_if_connect_cb(struct mg_connection *nc, int err) {
  DBG(("%p connect, err=%d", nc, err));
  nc->flags &= ~MG_F_CONNECTING;
  if (err != 0) {
    nc->flags |= MG_F_CLOSE_IMMEDIATELY;
  }
  mg_call(nc, NULL, MG_EV_CONNECT, &err);
}

#ifndef MG_DISABLE_RESOLVER
/*
 * Callback for the async resolver on mg_connect_opt() call.
 * Main task of this function is to trigger MG_EV_CONNECT event with
 *    either failure (and dealloc the connection)
 *    or success (and proceed with connect()
 */
static void resolve_cb(struct mg_dns_message *msg, void *data,
                       enum mg_resolve_err e) {
  struct mg_connection *nc = (struct mg_connection *) data;
  int i;
  int failure = -1;

  nc->flags &= ~MG_F_RESOLVING;
  if (msg != NULL) {
    /*
     * Take the first DNS A answer and run...
     */
    for (i = 0; i < msg->num_answers; i++) {
      if (msg->answers[i].rtype == MG_DNS_A_RECORD) {
        /*
         * Async resolver guarantees that there is at least one answer.
         * TODO(lsm): handle IPv6 answers too
         */
        mg_dns_parse_record_data(msg, &msg->answers[i], &nc->sa.sin.sin_addr,
                                 4);
        mg_do_connect(nc, nc->flags & MG_F_UDP ? SOCK_DGRAM : SOCK_STREAM,
                      &nc->sa);
        return;
      }
    }
  }

  if (e == MG_RESOLVE_TIMEOUT) {
    double now = mg_time();
    mg_call(nc, NULL, MG_EV_TIMER, &now);
  }

  /*
   * If we get there was no MG_DNS_A_RECORD in the answer
   */
  mg_call(nc, NULL, MG_EV_CONNECT, &failure);
  mg_call(nc, NULL, MG_EV_CLOSE, NULL);
  mg_destroy_conn(nc, 1 /* destroy_if */);
}
#endif

struct mg_connection *mg_connect(struct mg_mgr *mgr, const char *address,
                                 mg_event_handler_t callback) {
  struct mg_connect_opts opts;
  memset(&opts, 0, sizeof(opts));
  return mg_connect_opt(mgr, address, callback, opts);
}

#ifdef MG_ENABLE_SSL
static void mg_set_ssl_server_name(struct mg_connection *nc,
                                   const char *server_name) {
  DBG(("%p '%s'", nc, server_name));
#ifdef SSL_KRYPTON
  SSL_CTX_kr_set_verify_name(nc->ssl_ctx, server_name);
#elif defined(MG_SOCKET_SIMPLELINK)
  nc->ssl_server_name = strdup(server_name);
#else
  /* TODO(rojer): Implement server name verification on OpenSSL. */
  (void) nc;
  (void) server_name;
#endif
}
#endif /* MG_ENABLE_SSL */

struct mg_connection *mg_connect_opt(struct mg_mgr *mgr, const char *address,
                                     mg_event_handler_t callback,
                                     struct mg_connect_opts opts) {
  struct mg_connection *nc = NULL;
  int proto, rc;
  struct mg_add_sock_opts add_sock_opts;
  char host[MG_MAX_HOST_LEN];

  MG_COPY_COMMON_CONNECTION_OPTIONS(&add_sock_opts, &opts);

  if ((nc = mg_create_connection(mgr, callback, add_sock_opts)) == NULL) {
    return NULL;
  }

  if ((rc = mg_parse_address(address, &nc->sa, &proto, host, sizeof(host))) <
      0) {
    /* Address is malformed */
    MG_SET_PTRPTR(opts.error_string, "cannot parse address");
    mg_destroy_conn(nc, 1 /* destroy_if */);
    return NULL;
  }

  nc->flags |= opts.flags & _MG_ALLOWED_CONNECT_FLAGS_MASK;
  nc->flags |= (proto == SOCK_DGRAM) ? MG_F_UDP : 0;
  nc->user_data = opts.user_data;

#ifdef MG_ENABLE_SSL
  LOG(LL_DEBUG,
      ("%p %s %s,%s,%s", nc, address, (opts.ssl_cert ? opts.ssl_cert : "-"),
       (opts.ssl_key ? opts.ssl_key : "-"),
       (opts.ssl_ca_cert ? opts.ssl_ca_cert : "-")));

  if (opts.ssl_cert != NULL || opts.ssl_ca_cert != NULL) {
    const char *err =
        mg_set_ssl2(nc, opts.ssl_cert, opts.ssl_key, opts.ssl_ca_cert);
    if (err != NULL) {
      MG_SET_PTRPTR(opts.error_string, err);
      mg_destroy_conn(nc, 1 /* destroy_if */);
      return NULL;
    }
  }
  if (opts.ssl_ca_cert != NULL && opts.ssl_server_name != NULL &&
      strcmp(opts.ssl_server_name, "*") != 0) {
    mg_set_ssl_server_name(nc, opts.ssl_server_name);
  }
#endif /* MG_ENABLE_SSL */

  if (rc == 0) {
#ifndef MG_DISABLE_RESOLVER
    /*
     * DNS resolution is required for host.
     * mg_parse_address() fills port in nc->sa, which we pass to resolve_cb()
     */
    struct mg_connection *dns_conn = NULL;
    struct mg_resolve_async_opts o;
    memset(&o, 0, sizeof(o));
    o.dns_conn = &dns_conn;
    if (mg_resolve_async_opt(nc->mgr, host, MG_DNS_A_RECORD, resolve_cb, nc,
                             o) != 0) {
      MG_SET_PTRPTR(opts.error_string, "cannot schedule DNS lookup");
      mg_destroy_conn(nc, 1 /* destroy_if */);
      return NULL;
    }
    nc->priv_2 = dns_conn;
    nc->flags |= MG_F_RESOLVING;
#ifdef MG_ENABLE_SSL
    if (opts.ssl_ca_cert != NULL && opts.ssl_server_name == NULL) {
      mg_set_ssl_server_name(nc, host);
    }
#endif
    return nc;
#else
    MG_SET_PTRPTR(opts.error_string, "Resolver is disabled");
    mg_destroy_conn(nc, 1 /* destroy_if */);
    return NULL;
#endif
  } else {
    /* Address is parsed and resolved to IP. proceed with connect() */
    return mg_do_connect(nc, proto, &nc->sa);
  }
}

struct mg_connection *mg_bind(struct mg_mgr *srv, const char *address,
                              mg_event_handler_t event_handler) {
  struct mg_bind_opts opts;
  memset(&opts, 0, sizeof(opts));
  return mg_bind_opt(srv, address, event_handler, opts);
}

struct mg_connection *mg_bind_opt(struct mg_mgr *mgr, const char *address,
                                  mg_event_handler_t callback,
                                  struct mg_bind_opts opts) {
  union socket_address sa;
  struct mg_connection *nc = NULL;
  int proto, rc;
  struct mg_add_sock_opts add_sock_opts;
  char host[MG_MAX_HOST_LEN];

  MG_COPY_COMMON_CONNECTION_OPTIONS(&add_sock_opts, &opts);

  if (mg_parse_address(address, &sa, &proto, host, sizeof(host)) <= 0) {
    MG_SET_PTRPTR(opts.error_string, "cannot parse address");
    return NULL;
  }

  nc = mg_create_connection(mgr, callback, add_sock_opts);
  if (nc == NULL) {
    return NULL;
  }

  nc->sa = sa;
  nc->flags |= MG_F_LISTENING;
  if (proto == SOCK_DGRAM) nc->flags |= MG_F_UDP;

#ifdef MG_ENABLE_SSL
  DBG(("%p %s %s %s %s", nc, address, (opts.ssl_cert ? opts.ssl_cert : ""),
       (opts.ssl_key ? opts.ssl_key : ""),
       (opts.ssl_ca_cert ? opts.ssl_ca_cert : "")));

  if (opts.ssl_cert != NULL || opts.ssl_ca_cert != NULL) {
    const char *err =
        mg_set_ssl2(nc, opts.ssl_cert, opts.ssl_key, opts.ssl_ca_cert);
    if (err != NULL) {
      MG_SET_PTRPTR(opts.error_string, err);
      mg_destroy_conn(nc, 1 /* destroy_if */);
      return NULL;
    }
  }
#endif /* MG_ENABLE_SSL */

  if (nc->flags & MG_F_UDP) {
    rc = mg_if_listen_udp(nc, &nc->sa);
  } else {
    rc = mg_if_listen_tcp(nc, &nc->sa);
  }
  if (rc != 0) {
    DBG(("Failed to open listener: %d", rc));
    MG_SET_PTRPTR(opts.error_string, "failed to open listener");
    mg_destroy_conn(nc, 1 /* destroy_if */);
    return NULL;
  }
  mg_add_conn(nc->mgr, nc);

  return nc;
}

struct mg_connection *mg_next(struct mg_mgr *s, struct mg_connection *conn) {
  return conn == NULL ? s->active_connections : conn->next;
}

#ifndef MG_DISABLE_SOCKETPAIR
void mg_broadcast(struct mg_mgr *mgr, mg_event_handler_t cb, void *data,
                  size_t len) {
  struct ctl_msg ctl_msg;

  /*
   * Mongoose manager has a socketpair, `struct mg_mgr::ctl`,
   * where `mg_broadcast()` pushes the message.
   * `mg_mgr_poll()` wakes up, reads a message from the socket pair, and calls
   * specified callback for each connection. Thus the callback function executes
   * in event manager thread.
   */
  if (mgr->ctl[0] != INVALID_SOCKET && data != NULL &&
      len < sizeof(ctl_msg.message)) {
    size_t dummy;

    ctl_msg.callback = cb;
    memcpy(ctl_msg.message, data, len);
    dummy = MG_SEND_FUNC(mgr->ctl[0], (char *) &ctl_msg,
                         offsetof(struct ctl_msg, message) + len, 0);
    dummy = MG_RECV_FUNC(mgr->ctl[0], (char *) &len, 1, 0);
    (void) dummy; /* https://gcc.gnu.org/bugzilla/show_bug.cgi?id=25509 */
  }
}
#endif /* MG_DISABLE_SOCKETPAIR */

static int isbyte(int n) {
  return n >= 0 && n <= 255;
}

static int parse_net(const char *spec, uint32_t *net, uint32_t *mask) {
  int n, a, b, c, d, slash = 32, len = 0;

  if ((sscanf(spec, "%d.%d.%d.%d/%d%n", &a, &b, &c, &d, &slash, &n) == 5 ||
       sscanf(spec, "%d.%d.%d.%d%n", &a, &b, &c, &d, &n) == 4) &&
      isbyte(a) && isbyte(b) && isbyte(c) && isbyte(d) && slash >= 0 &&
      slash < 33) {
    len = n;
    *net =
        ((uint32_t) a << 24) | ((uint32_t) b << 16) | ((uint32_t) c << 8) | d;
    *mask = slash ? 0xffffffffU << (32 - slash) : 0;
  }

  return len;
}

int mg_check_ip_acl(const char *acl, uint32_t remote_ip) {
  int allowed, flag;
  uint32_t net, mask;
  struct mg_str vec;

  /* If any ACL is set, deny by default */
  allowed = (acl == NULL || *acl == '\0') ? '+' : '-';

  while ((acl = mg_next_comma_list_entry(acl, &vec, NULL)) != NULL) {
    flag = vec.p[0];
    if ((flag != '+' && flag != '-') ||
        parse_net(&vec.p[1], &net, &mask) == 0) {
      return -1;
    }

    if (net == (remote_ip & mask)) {
      allowed = flag;
    }
  }

  DBG(("%08x %c", remote_ip, allowed));
  return allowed == '+';
}

/* Move data from one connection to another */
void mg_forward(struct mg_connection *from, struct mg_connection *to) {
  mg_send(to, from->recv_mbuf.buf, from->recv_mbuf.len);
  mbuf_remove(&from->recv_mbuf, from->recv_mbuf.len);
}

double mg_set_timer(struct mg_connection *c, double timestamp) {
  double result = c->ev_timer_time;
  c->ev_timer_time = timestamp;
  /*
   * If this connection is resolving, it's not in the list of active
   * connections, so not processed yet. It has a DNS resolver connection
   * linked to it. Set up a timer for the DNS connection.
   */
  DBG(("%p %p %d -> %lu", c, c->priv_2, c->flags & MG_F_RESOLVING,
       (unsigned long) timestamp));
  if ((c->flags & MG_F_RESOLVING) && c->priv_2 != NULL) {
    ((struct mg_connection *) c->priv_2)->ev_timer_time = timestamp;
  }
  return result;
}

struct mg_connection *mg_add_sock_opt(struct mg_mgr *s, sock_t sock,
                                      mg_event_handler_t callback,
                                      struct mg_add_sock_opts opts) {
  struct mg_connection *nc = mg_create_connection_base(s, callback, opts);
  if (nc != NULL) {
    mg_sock_set(nc, sock);
    mg_add_conn(nc->mgr, nc);
  }
  return nc;
}

struct mg_connection *mg_add_sock(struct mg_mgr *s, sock_t sock,
                                  mg_event_handler_t callback) {
  struct mg_add_sock_opts opts;
  memset(&opts, 0, sizeof(opts));
  return mg_add_sock_opt(s, sock, callback, opts);
}

double mg_time(void) {
  return cs_time();
}
