/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#ifndef MG_DISABLE_HTTP

#include "mongoose/src/internal.h"
#include "mongoose/src/util.h"
#include "common/sha1.h"
#include "common/md5.h"

#ifndef MG_DISABLE_HTTP_WEBSOCKET
#define MG_WS_NO_HOST_HEADER_MAGIC ((char *) 0x1)
#endif

/* CGI requires socketpair. */
#if defined(MG_DISABLE_SOCKETPAIR) && !defined(MG_DISABLE_CGI)
#define MG_DISABLE_CGI 1
#endif

static const char *mg_version_header = "Mongoose/" MG_VERSION;

enum mg_http_proto_data_type { DATA_NONE, DATA_FILE, DATA_PUT };

struct mg_http_proto_data_file {
  FILE *fp;      /* Opened file. */
  int64_t cl;    /* Content-Length. How many bytes to send. */
  int64_t sent;  /* How many bytes have been already sent. */
  int keepalive; /* Keep connection open after sending. */
  enum mg_http_proto_data_type type;
};

struct mg_http_proto_data_cgi {
  struct mg_connection *cgi_nc;
};

struct mg_http_proto_data_chuncked {
  int64_t body_len; /* How many bytes of chunked body was reassembled. */
};

struct mg_http_endpoint {
  struct mg_http_endpoint *next;
  const char *name;
  size_t name_len;
  mg_event_handler_t handler;
};

enum mg_http_multipart_stream_state {
  MPS_BEGIN,
  MPS_WAITING_FOR_BOUNDARY,
  MPS_WAITING_FOR_CHUNK,
  MPS_GOT_CHUNK,
  MPS_GOT_BOUNDARY,
  MPS_FINALIZE,
  MPS_FINISHED
};

struct mg_http_multipart_stream {
  const char *boundary;
  int boundary_len;
  const char *var_name;
  const char *file_name;
  void *user_data;
  int prev_io_len;
  enum mg_http_multipart_stream_state state;
  int processing_part;
};

struct mg_http_proto_data {
#ifndef MG_DISABLE_FILESYSTEM
  struct mg_http_proto_data_file file;
#endif
#ifndef MG_DISABLE_CGI
  struct mg_http_proto_data_cgi cgi;
#endif
#ifdef MG_ENABLE_HTTP_STREAMING_MULTIPART
  struct mg_http_multipart_stream mp_stream;
#endif
  struct mg_http_proto_data_chuncked chunk;
  struct mg_http_endpoint *endpoints;
  mg_event_handler_t endpoint_handler;
};

static void mg_http_conn_destructor(void *proto_data);

static struct mg_http_proto_data *mg_http_get_proto_data(
    struct mg_connection *c) {
  if (c->proto_data == NULL) {
    c->proto_data = MG_CALLOC(1, sizeof(struct mg_http_proto_data));
    c->proto_data_destructor = mg_http_conn_destructor;
  }

  return (struct mg_http_proto_data *) c->proto_data;
}

#ifdef MG_ENABLE_HTTP_STREAMING_MULTIPART
static void mg_http_free_proto_data_mp_stream(
    struct mg_http_multipart_stream *mp) {
  free((void *) mp->boundary);
  free((void *) mp->var_name);
  free((void *) mp->file_name);
  memset(mp, 0, sizeof(*mp));
}
#endif

#ifndef MG_DISABLE_FILESYSTEM
static void mg_http_free_proto_data_file(struct mg_http_proto_data_file *d) {
  if (d != NULL) {
    if (d->fp != NULL) {
      fclose(d->fp);
    }
    memset(d, 0, sizeof(struct mg_http_proto_data_file));
  }
}
#endif

#ifndef MG_DISABLE_CGI
static void mg_http_free_proto_data_cgi(struct mg_http_proto_data_cgi *d) {
  if (d != NULL) {
    if (d->cgi_nc != NULL) d->cgi_nc->flags |= MG_F_CLOSE_IMMEDIATELY;
    memset(d, 0, sizeof(struct mg_http_proto_data_cgi));
  }
}
#endif

static void mg_http_free_proto_data_endpoints(struct mg_http_endpoint **ep) {
  struct mg_http_endpoint *current = *ep;

  while (current != NULL) {
    struct mg_http_endpoint *tmp = current->next;
    free((void *) current->name);
    free(current);
    current = tmp;
  }

  ep = NULL;
}

static void mg_http_conn_destructor(void *proto_data) {
  struct mg_http_proto_data *pd = (struct mg_http_proto_data *) proto_data;
#ifndef MG_DISABLE_FILESYSTEM
  mg_http_free_proto_data_file(&pd->file);
#endif
#ifndef MG_DISABLE_CGI
  mg_http_free_proto_data_cgi(&pd->cgi);
#endif
#ifdef MG_ENABLE_HTTP_STREAMING_MULTIPART
  mg_http_free_proto_data_mp_stream(&pd->mp_stream);
#endif
  mg_http_free_proto_data_endpoints(&pd->endpoints);
  free(proto_data);
}

/*
 * This structure helps to create an environment for the spawned CGI program.
 * Environment is an array of "VARIABLE=VALUE\0" ASCIIZ strings,
 * last element must be NULL.
 * However, on Windows there is a requirement that all these VARIABLE=VALUE\0
 * strings must reside in a contiguous buffer. The end of the buffer is
 * marked by two '\0' characters.
 * We satisfy both worlds: we create an envp array (which is vars), all
 * entries are actually pointers inside buf.
 */
struct mg_cgi_env_block {
  struct mg_connection *nc;
  char buf[MG_CGI_ENVIRONMENT_SIZE];       /* Environment buffer */
  const char *vars[MG_MAX_CGI_ENVIR_VARS]; /* char *envp[] */
  int len;                                 /* Space taken */
  int nvars;                               /* Number of variables in envp[] */
};

#ifndef MG_DISABLE_FILESYSTEM

#define MIME_ENTRY(_ext, _type) \
  { _ext, sizeof(_ext) - 1, _type }
static const struct {
  const char *extension;
  size_t ext_len;
  const char *mime_type;
} mg_static_builtin_mime_types[] = {
    MIME_ENTRY("html", "text/html"),
    MIME_ENTRY("html", "text/html"),
    MIME_ENTRY("htm", "text/html"),
    MIME_ENTRY("shtm", "text/html"),
    MIME_ENTRY("shtml", "text/html"),
    MIME_ENTRY("css", "text/css"),
    MIME_ENTRY("js", "application/x-javascript"),
    MIME_ENTRY("ico", "image/x-icon"),
    MIME_ENTRY("gif", "image/gif"),
    MIME_ENTRY("jpg", "image/jpeg"),
    MIME_ENTRY("jpeg", "image/jpeg"),
    MIME_ENTRY("png", "image/png"),
    MIME_ENTRY("svg", "image/svg+xml"),
    MIME_ENTRY("txt", "text/plain"),
    MIME_ENTRY("torrent", "application/x-bittorrent"),
    MIME_ENTRY("wav", "audio/x-wav"),
    MIME_ENTRY("mp3", "audio/x-mp3"),
    MIME_ENTRY("mid", "audio/mid"),
    MIME_ENTRY("m3u", "audio/x-mpegurl"),
    MIME_ENTRY("ogg", "application/ogg"),
    MIME_ENTRY("ram", "audio/x-pn-realaudio"),
    MIME_ENTRY("xml", "text/xml"),
    MIME_ENTRY("ttf", "application/x-font-ttf"),
    MIME_ENTRY("json", "application/json"),
    MIME_ENTRY("xslt", "application/xml"),
    MIME_ENTRY("xsl", "application/xml"),
    MIME_ENTRY("ra", "audio/x-pn-realaudio"),
    MIME_ENTRY("doc", "application/msword"),
    MIME_ENTRY("exe", "application/octet-stream"),
    MIME_ENTRY("zip", "application/x-zip-compressed"),
    MIME_ENTRY("xls", "application/excel"),
    MIME_ENTRY("tgz", "application/x-tar-gz"),
    MIME_ENTRY("tar", "application/x-tar"),
    MIME_ENTRY("gz", "application/x-gunzip"),
    MIME_ENTRY("arj", "application/x-arj-compressed"),
    MIME_ENTRY("rar", "application/x-rar-compressed"),
    MIME_ENTRY("rtf", "application/rtf"),
    MIME_ENTRY("pdf", "application/pdf"),
    MIME_ENTRY("swf", "application/x-shockwave-flash"),
    MIME_ENTRY("mpg", "video/mpeg"),
    MIME_ENTRY("webm", "video/webm"),
    MIME_ENTRY("mpeg", "video/mpeg"),
    MIME_ENTRY("mov", "video/quicktime"),
    MIME_ENTRY("mp4", "video/mp4"),
    MIME_ENTRY("m4v", "video/x-m4v"),
    MIME_ENTRY("asf", "video/x-ms-asf"),
    MIME_ENTRY("avi", "video/x-msvideo"),
    MIME_ENTRY("bmp", "image/bmp"),
    {NULL, 0, NULL}};

#ifndef MG_DISABLE_DAV
static int mg_mkdir(const char *path, uint32_t mode) {
#ifndef _WIN32
  return mkdir(path, mode);
#else
  (void) mode;
  return _mkdir(path);
#endif
}
#endif

static struct mg_str mg_get_mime_type(const char *path, const char *dflt,
                                      const struct mg_serve_http_opts *opts) {
  const char *ext, *overrides;
  size_t i, path_len;
  struct mg_str r, k, v;

  path_len = strlen(path);

  overrides = opts->custom_mime_types;
  while ((overrides = mg_next_comma_list_entry(overrides, &k, &v)) != NULL) {
    ext = path + (path_len - k.len);
    if (path_len > k.len && mg_vcasecmp(&k, ext) == 0) {
      return v;
    }
  }

  for (i = 0; mg_static_builtin_mime_types[i].extension != NULL; i++) {
    ext = path + (path_len - mg_static_builtin_mime_types[i].ext_len);
    if (path_len > mg_static_builtin_mime_types[i].ext_len && ext[-1] == '.' &&
        mg_casecmp(ext, mg_static_builtin_mime_types[i].extension) == 0) {
      r.p = mg_static_builtin_mime_types[i].mime_type;
      r.len = strlen(r.p);
      return r;
    }
  }

  r.p = dflt;
  r.len = strlen(r.p);
  return r;
}
#endif

/*
 * Check whether full request is buffered. Return:
 *   -1  if request is malformed
 *    0  if request is not yet fully buffered
 *   >0  actual request length, including last \r\n\r\n
 */
static int mg_http_get_request_len(const char *s, int buf_len) {
  const unsigned char *buf = (unsigned char *) s;
  int i;

  for (i = 0; i < buf_len; i++) {
    if (!isprint(buf[i]) && buf[i] != '\r' && buf[i] != '\n' && buf[i] < 128) {
      return -1;
    } else if (buf[i] == '\n' && i + 1 < buf_len && buf[i + 1] == '\n') {
      return i + 2;
    } else if (buf[i] == '\n' && i + 2 < buf_len && buf[i + 1] == '\r' &&
               buf[i + 2] == '\n') {
      return i + 3;
    }
  }

  return 0;
}

static const char *mg_http_parse_headers(const char *s, const char *end,
                                         int len, struct http_message *req) {
  int i = 0;
  while (i < (int) ARRAY_SIZE(req->header_names) - 1) {
    struct mg_str *k = &req->header_names[i], *v = &req->header_values[i];

    s = mg_skip(s, end, ": ", k);
    s = mg_skip(s, end, "\r\n", v);

    while (v->len > 0 && v->p[v->len - 1] == ' ') {
      v->len--; /* Trim trailing spaces in header value */
    }

    /*
     * If header value is empty - skip it and go to next (if any).
     * NOTE: Do not add it to headers_values because such addition changes API
     * behaviour
     */
    if (k->len != 0 && v->len == 0) {
      continue;
    }

    if (k->len == 0 || v->len == 0) {
      k->p = v->p = NULL;
      k->len = v->len = 0;
      break;
    }

    if (!mg_ncasecmp(k->p, "Content-Length", 14)) {
      req->body.len = (size_t) to64(v->p);
      req->message.len = len + req->body.len;
    }

    i++;
  }

  return s;
}

int mg_parse_http(const char *s, int n, struct http_message *hm, int is_req) {
  const char *end, *qs;
  int len = mg_http_get_request_len(s, n);

  if (len <= 0) return len;

  memset(hm, 0, sizeof(*hm));
  hm->message.p = s;
  hm->body.p = s + len;
  hm->message.len = hm->body.len = (size_t) ~0;
  end = s + len;

  /* Request is fully buffered. Skip leading whitespaces. */
  while (s < end && isspace(*(unsigned char *) s)) s++;

  if (is_req) {
    /* Parse request line: method, URI, proto */
    s = mg_skip(s, end, " ", &hm->method);
    s = mg_skip(s, end, " ", &hm->uri);
    s = mg_skip(s, end, "\r\n", &hm->proto);
    if (hm->uri.p <= hm->method.p || hm->proto.p <= hm->uri.p) return -1;

    /* If URI contains '?' character, initialize query_string */
    if ((qs = (char *) memchr(hm->uri.p, '?', hm->uri.len)) != NULL) {
      hm->query_string.p = qs + 1;
      hm->query_string.len = &hm->uri.p[hm->uri.len] - (qs + 1);
      hm->uri.len = qs - hm->uri.p;
    }
  } else {
    s = mg_skip(s, end, " ", &hm->proto);
    if (end - s < 4 || s[3] != ' ') return -1;
    hm->resp_code = atoi(s);
    if (hm->resp_code < 100 || hm->resp_code >= 600) return -1;
    s += 4;
    s = mg_skip(s, end, "\r\n", &hm->resp_status_msg);
  }

  s = mg_http_parse_headers(s, end, len, hm);

  /*
   * mg_parse_http() is used to parse both HTTP requests and HTTP
   * responses. If HTTP response does not have Content-Length set, then
   * body is read until socket is closed, i.e. body.len is infinite (~0).
   *
   * For HTTP requests though, according to
   * http://tools.ietf.org/html/rfc7231#section-8.1.3,
   * only POST and PUT methods have defined body semantics.
   * Therefore, if Content-Length is not specified and methods are
   * not one of PUT or POST, set body length to 0.
   *
   * So,
   * if it is HTTP request, and Content-Length is not set,
   * and method is not (PUT or POST) then reset body length to zero.
   */
  if (hm->body.len == (size_t) ~0 && is_req &&
      mg_vcasecmp(&hm->method, "PUT") != 0 &&
      mg_vcasecmp(&hm->method, "POST") != 0) {
    hm->body.len = 0;
    hm->message.len = len;
  }

  return len;
}

struct mg_str *mg_get_http_header(struct http_message *hm, const char *name) {
  size_t i, len = strlen(name);

  for (i = 0; hm->header_names[i].len > 0; i++) {
    struct mg_str *h = &hm->header_names[i], *v = &hm->header_values[i];
    if (h->p != NULL && h->len == len && !mg_ncasecmp(h->p, name, len))
      return v;
  }

  return NULL;
}

#ifndef MG_DISABLE_HTTP_WEBSOCKET

static int mg_is_ws_fragment(unsigned char flags) {
  return (flags & 0x80) == 0 || (flags & 0x0f) == 0;
}

static int mg_is_ws_first_fragment(unsigned char flags) {
  return (flags & 0x80) == 0 && (flags & 0x0f) != 0;
}

static void mg_handle_incoming_websocket_frame(struct mg_connection *nc,
                                               struct websocket_message *wsm) {
  if (wsm->flags & 0x8) {
    mg_call(nc, nc->handler, MG_EV_WEBSOCKET_CONTROL_FRAME, wsm);
  } else {
    mg_call(nc, nc->handler, MG_EV_WEBSOCKET_FRAME, wsm);
  }
}

static int mg_deliver_websocket_data(struct mg_connection *nc) {
  /* Using unsigned char *, cause of integer arithmetic below */
  uint64_t i, data_len = 0, frame_len = 0, buf_len = nc->recv_mbuf.len, len,
              mask_len = 0, header_len = 0;
  unsigned char *p = (unsigned char *) nc->recv_mbuf.buf, *buf = p,
                *e = p + buf_len;
  unsigned *sizep = (unsigned *) &p[1]; /* Size ptr for defragmented frames */
  int ok, reass = buf_len > 0 && mg_is_ws_fragment(p[0]) &&
                  !(nc->flags & MG_F_WEBSOCKET_NO_DEFRAG);

  /* If that's a continuation frame that must be reassembled, handle it */
  if (reass && !mg_is_ws_first_fragment(p[0]) &&
      buf_len >= 1 + sizeof(*sizep) && buf_len >= 1 + sizeof(*sizep) + *sizep) {
    buf += 1 + sizeof(*sizep) + *sizep;
    buf_len -= 1 + sizeof(*sizep) + *sizep;
  }

  if (buf_len >= 2) {
    len = buf[1] & 127;
    mask_len = buf[1] & 128 ? 4 : 0;
    if (len < 126 && buf_len >= mask_len) {
      data_len = len;
      header_len = 2 + mask_len;
    } else if (len == 126 && buf_len >= 4 + mask_len) {
      header_len = 4 + mask_len;
      data_len = ntohs(*(uint16_t *) &buf[2]);
    } else if (buf_len >= 10 + mask_len) {
      header_len = 10 + mask_len;
      data_len = (((uint64_t) ntohl(*(uint32_t *) &buf[2])) << 32) +
                 ntohl(*(uint32_t *) &buf[6]);
    }
  }

  frame_len = header_len + data_len;
  ok = frame_len > 0 && frame_len <= buf_len;

  if (ok) {
    struct websocket_message wsm;

    wsm.size = (size_t) data_len;
    wsm.data = buf + header_len;
    wsm.flags = buf[0];

    /* Apply mask if necessary */
    if (mask_len > 0) {
      for (i = 0; i < data_len; i++) {
        buf[i + header_len] ^= (buf + header_len - mask_len)[i % 4];
      }
    }

    if (reass) {
      /* On first fragmented frame, nullify size */
      if (mg_is_ws_first_fragment(wsm.flags)) {
        mbuf_resize(&nc->recv_mbuf, nc->recv_mbuf.size + sizeof(*sizep));
        p[0] &= ~0x0f; /* Next frames will be treated as continuation */
        buf = p + 1 + sizeof(*sizep);
        *sizep = 0; /* TODO(lsm): fix. this can stomp over frame data */
      }

      /* Append this frame to the reassembled buffer */
      memmove(buf, wsm.data, e - wsm.data);
      (*sizep) += wsm.size;
      nc->recv_mbuf.len -= wsm.data - buf;

      /* On last fragmented frame - call user handler and remove data */
      if (wsm.flags & 0x80) {
        wsm.data = p + 1 + sizeof(*sizep);
        wsm.size = *sizep;
        mg_handle_incoming_websocket_frame(nc, &wsm);
        mbuf_remove(&nc->recv_mbuf, 1 + sizeof(*sizep) + *sizep);
      }
    } else {
      /* TODO(lsm): properly handle OOB control frames during defragmentation */
      mg_handle_incoming_websocket_frame(nc, &wsm);
      mbuf_remove(&nc->recv_mbuf, (size_t) frame_len); /* Cleanup frame */
    }

    /* If client closes, close too */
    if ((buf[0] & 0x0f) == WEBSOCKET_OP_CLOSE) {
      nc->flags |= MG_F_SEND_AND_CLOSE;
    }
  }

  return ok;
}

struct ws_mask_ctx {
  size_t pos; /* zero means unmasked */
  uint32_t mask;
};

static uint32_t mg_ws_random_mask(void) {
  uint32_t mask;
/*
 * The spec requires WS client to generate hard to
 * guess mask keys. From RFC6455, Section 5.3:
 *
 * The unpredictability of the masking key is essential to prevent
 * authors of malicious applications from selecting the bytes that appear on
 * the wire.
 *
 * Hence this feature is essential when the actual end user of this API
 * is untrusted code that wouldn't have access to a lower level net API
 * anyway (e.g. web browsers). Hence this feature is low prio for most
 * mongoose use cases and thus can be disabled, e.g. when porting to a platform
 * that lacks rand().
 */
#ifdef MG_DISABLE_WS_RANDOM_MASK
  mask = 0xefbeadde; /* generated with a random number generator, I swear */
#else
  if (sizeof(long) >= 4) {
    mask = (uint32_t) rand();
  } else if (sizeof(long) == 2) {
    mask = (uint32_t) rand() << 16 | (uint32_t) rand();
  }
#endif
  return mask;
}

static void mg_send_ws_header(struct mg_connection *nc, int op, size_t len,
                              struct ws_mask_ctx *ctx) {
  int header_len;
  unsigned char header[10];

  header[0] = (op & WEBSOCKET_DONT_FIN ? 0x0 : 0x80) + (op & 0x0f);
  if (len < 126) {
    header[1] = (unsigned char) len;
    header_len = 2;
  } else if (len < 65535) {
    uint16_t tmp = htons((uint16_t) len);
    header[1] = 126;
    memcpy(&header[2], &tmp, sizeof(tmp));
    header_len = 4;
  } else {
    uint32_t tmp;
    header[1] = 127;
    tmp = htonl((uint32_t)((uint64_t) len >> 32));
    memcpy(&header[2], &tmp, sizeof(tmp));
    tmp = htonl((uint32_t)(len & 0xffffffff));
    memcpy(&header[6], &tmp, sizeof(tmp));
    header_len = 10;
  }

  /* client connections enable masking */
  if (nc->listener == NULL) {
    header[1] |= 1 << 7; /* set masking flag */
    mg_send(nc, header, header_len);
    ctx->mask = mg_ws_random_mask();
    mg_send(nc, &ctx->mask, sizeof(ctx->mask));
    ctx->pos = nc->send_mbuf.len;
  } else {
    mg_send(nc, header, header_len);
    ctx->pos = 0;
  }
}

static void mg_ws_mask_frame(struct mbuf *mbuf, struct ws_mask_ctx *ctx) {
  size_t i;
  if (ctx->pos == 0) return;
  for (i = 0; i < (mbuf->len - ctx->pos); i++) {
    mbuf->buf[ctx->pos + i] ^= ((char *) &ctx->mask)[i % 4];
  }
}

void mg_send_websocket_frame(struct mg_connection *nc, int op, const void *data,
                             size_t len) {
  struct ws_mask_ctx ctx;
  DBG(("%p %d %d", nc, op, (int) len));
  mg_send_ws_header(nc, op, len, &ctx);
  mg_send(nc, data, len);

  mg_ws_mask_frame(&nc->send_mbuf, &ctx);

  if (op == WEBSOCKET_OP_CLOSE) {
    nc->flags |= MG_F_SEND_AND_CLOSE;
  }
}

void mg_send_websocket_framev(struct mg_connection *nc, int op,
                              const struct mg_str *strv, int strvcnt) {
  struct ws_mask_ctx ctx;
  int i;
  int len = 0;
  for (i = 0; i < strvcnt; i++) {
    len += strv[i].len;
  }

  mg_send_ws_header(nc, op, len, &ctx);

  for (i = 0; i < strvcnt; i++) {
    mg_send(nc, strv[i].p, strv[i].len);
  }

  mg_ws_mask_frame(&nc->send_mbuf, &ctx);

  if (op == WEBSOCKET_OP_CLOSE) {
    nc->flags |= MG_F_SEND_AND_CLOSE;
  }
}

void mg_printf_websocket_frame(struct mg_connection *nc, int op,
                               const char *fmt, ...) {
  char mem[MG_VPRINTF_BUFFER_SIZE], *buf = mem;
  va_list ap;
  int len;

  va_start(ap, fmt);
  if ((len = mg_avprintf(&buf, sizeof(mem), fmt, ap)) > 0) {
    mg_send_websocket_frame(nc, op, buf, len);
  }
  va_end(ap);

  if (buf != mem && buf != NULL) {
    MG_FREE(buf);
  }
}

static void mg_websocket_handler(struct mg_connection *nc, int ev,
                                 void *ev_data) {
  mg_call(nc, nc->handler, ev, ev_data);

  switch (ev) {
    case MG_EV_RECV:
      do {
      } while (mg_deliver_websocket_data(nc));
      break;
    case MG_EV_POLL:
      /* Ping idle websocket connections */
      {
        time_t now = *(time_t *) ev_data;
        if (nc->flags & MG_F_IS_WEBSOCKET &&
            now > nc->last_io_time + MG_WEBSOCKET_PING_INTERVAL_SECONDS) {
          mg_send_websocket_frame(nc, WEBSOCKET_OP_PING, "", 0);
        }
      }
      break;
    default:
      break;
  }
}

#ifndef MG_EXT_SHA1
static void mg_hash_sha1_v(size_t num_msgs, const uint8_t *msgs[],
                           const size_t *msg_lens, uint8_t *digest) {
  size_t i;
  cs_sha1_ctx sha_ctx;
  cs_sha1_init(&sha_ctx);
  for (i = 0; i < num_msgs; i++) {
    cs_sha1_update(&sha_ctx, msgs[i], msg_lens[i]);
  }
  cs_sha1_final(digest, &sha_ctx);
}
#else
extern void mg_hash_sha1_v(size_t num_msgs, const uint8_t *msgs[],
                           const size_t *msg_lens, uint8_t *digest);
#endif

static void mg_ws_handshake(struct mg_connection *nc,
                            const struct mg_str *key) {
  static const char *magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  const uint8_t *msgs[2] = {(const uint8_t *) key->p, (const uint8_t *) magic};
  const size_t msg_lens[2] = {key->len, 36};
  unsigned char sha[20];
  char b64_sha[30];

  mg_hash_sha1_v(2, msgs, msg_lens, sha);
  mg_base64_encode(sha, sizeof(sha), b64_sha);
  mg_printf(nc, "%s%s%s",
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: ",
            b64_sha, "\r\n\r\n");
  DBG(("%p %.*s %s", nc, (int) key->len, key->p, b64_sha));
}

#endif /* MG_DISABLE_HTTP_WEBSOCKET */

#ifndef MG_DISABLE_FILESYSTEM
static void mg_http_transfer_file_data(struct mg_connection *nc) {
  struct mg_http_proto_data *pd = mg_http_get_proto_data(nc);
  char buf[MG_MAX_HTTP_SEND_MBUF];
  size_t n = 0, to_read = 0, left = (size_t)(pd->file.cl - pd->file.sent);

  if (pd->file.type == DATA_FILE) {
    struct mbuf *io = &nc->send_mbuf;
    if (io->len < sizeof(buf)) {
      to_read = sizeof(buf) - io->len;
    }

    if (left > 0 && to_read > left) {
      to_read = left;
    }

    if (to_read == 0) {
      /* Rate limiting. send_mbuf is too full, wait until it's drained. */
    } else if (pd->file.sent < pd->file.cl &&
               (n = fread(buf, 1, to_read, pd->file.fp)) > 0) {
      mg_send(nc, buf, n);
      pd->file.sent += n;
    } else {
      if (!pd->file.keepalive) nc->flags |= MG_F_SEND_AND_CLOSE;
      mg_http_free_proto_data_file(&pd->file);
    }
  } else if (pd->file.type == DATA_PUT) {
    struct mbuf *io = &nc->recv_mbuf;
    size_t to_write = left <= 0 ? 0 : left < io->len ? (size_t) left : io->len;
    size_t n = fwrite(io->buf, 1, to_write, pd->file.fp);
    if (n > 0) {
      mbuf_remove(io, n);
      pd->file.sent += n;
    }
    if (n == 0 || pd->file.sent >= pd->file.cl) {
      if (!pd->file.keepalive) nc->flags |= MG_F_SEND_AND_CLOSE;
      mg_http_free_proto_data_file(&pd->file);
    }
  }
#ifndef MG_DISABLE_CGI
  else if (pd->cgi.cgi_nc != NULL) {
    /* This is POST data that needs to be forwarded to the CGI process */
    if (pd->cgi.cgi_nc != NULL) {
      mg_forward(nc, pd->cgi.cgi_nc);
    } else {
      nc->flags |= MG_F_SEND_AND_CLOSE;
    }
  }
#endif
}
#endif /* MG_DISABLE_FILESYSTEM */

/*
 * Parse chunked-encoded buffer. Return 0 if the buffer is not encoded, or
 * if it's incomplete. If the chunk is fully buffered, return total number of
 * bytes in a chunk, and store data in `data`, `data_len`.
 */
static size_t mg_http_parse_chunk(char *buf, size_t len, char **chunk_data,
                                  size_t *chunk_len) {
  unsigned char *s = (unsigned char *) buf;
  size_t n = 0; /* scanned chunk length */
  size_t i = 0; /* index in s */

  /* Scan chunk length. That should be a hexadecimal number. */
  while (i < len && isxdigit(s[i])) {
    n *= 16;
    n += (s[i] >= '0' && s[i] <= '9') ? s[i] - '0' : tolower(s[i]) - 'a' + 10;
    i++;
  }

  /* Skip new line */
  if (i == 0 || i + 2 > len || s[i] != '\r' || s[i + 1] != '\n') {
    return 0;
  }
  i += 2;

  /* Record where the data is */
  *chunk_data = (char *) s + i;
  *chunk_len = n;

  /* Skip data */
  i += n;

  /* Skip new line */
  if (i == 0 || i + 2 > len || s[i] != '\r' || s[i + 1] != '\n') {
    return 0;
  }
  return i + 2;
}

MG_INTERNAL size_t mg_handle_chunked(struct mg_connection *nc,
                                     struct http_message *hm, char *buf,
                                     size_t blen) {
  struct mg_http_proto_data *pd = mg_http_get_proto_data(nc);
  char *data;
  size_t i, n, data_len, body_len, zero_chunk_received = 0;
  /* Find out piece of received data that is not yet reassembled */
  body_len = (size_t) pd->chunk.body_len;
  assert(blen >= body_len);

  /* Traverse all fully buffered chunks */
  for (i = body_len;
       (n = mg_http_parse_chunk(buf + i, blen - i, &data, &data_len)) > 0;
       i += n) {
    /* Collapse chunk data to the rest of HTTP body */
    memmove(buf + body_len, data, data_len);
    body_len += data_len;
    hm->body.len = body_len;

    if (data_len == 0) {
      zero_chunk_received = 1;
      i += n;
      break;
    }
  }

  if (i > body_len) {
    /* Shift unparsed content to the parsed body */
    assert(i <= blen);
    memmove(buf + body_len, buf + i, blen - i);
    memset(buf + body_len + blen - i, 0, i - body_len);
    nc->recv_mbuf.len -= i - body_len;
    pd->chunk.body_len = body_len;

    /* Send MG_EV_HTTP_CHUNK event */
    nc->flags &= ~MG_F_DELETE_CHUNK;
    mg_call(nc, nc->handler, MG_EV_HTTP_CHUNK, hm);

    /* Delete processed data if user set MG_F_DELETE_CHUNK flag */
    if (nc->flags & MG_F_DELETE_CHUNK) {
      memset(buf, 0, body_len);
      memmove(buf, buf + body_len, blen - i);
      nc->recv_mbuf.len -= body_len;
      hm->body.len = 0;
      pd->chunk.body_len = 0;
    }

    if (zero_chunk_received) {
      hm->message.len = (size_t) pd->chunk.body_len + blen - i;
    }
  }

  return body_len;
}

static mg_event_handler_t mg_http_get_endpoint_handler(
    struct mg_connection *nc, struct mg_str *uri_path) {
  struct mg_http_proto_data *pd;
  mg_event_handler_t ret = NULL;
  int matched, matched_max = 0;
  struct mg_http_endpoint *ep;

  if (nc == NULL) {
    return NULL;
  }

  pd = mg_http_get_proto_data(nc);

  ep = pd->endpoints;
  while (ep != NULL) {
    const struct mg_str name_s = {ep->name, ep->name_len};
    if ((matched = mg_match_prefix_n(name_s, *uri_path)) != -1) {
      if (matched > matched_max) {
        /* Looking for the longest suitable handler */
        ret = ep->handler;
        matched_max = matched;
      }
    }

    ep = ep->next;
  }

  return ret;
}

static void mg_http_call_endpoint_handler(struct mg_connection *nc, int ev,
                                          struct http_message *hm) {
  struct mg_http_proto_data *pd = mg_http_get_proto_data(nc);

  if (pd->endpoint_handler == NULL || ev == MG_EV_HTTP_REQUEST) {
    pd->endpoint_handler =
        ev == MG_EV_HTTP_REQUEST
            ? mg_http_get_endpoint_handler(nc->listener, &hm->uri)
            : NULL;
  }
  mg_call(nc, pd->endpoint_handler ? pd->endpoint_handler : nc->handler, ev,
          hm);
}

#ifdef MG_ENABLE_HTTP_STREAMING_MULTIPART
static void mg_http_multipart_continue(struct mg_connection *nc);

static void mg_http_multipart_begin(struct mg_connection *nc,
                                    struct http_message *hm, int req_len);

#endif

/*
 * lx106 compiler has a bug (TODO(mkm) report and insert tracking bug here)
 * If a big structure is declared in a big function, lx106 gcc will make it
 * even bigger (round up to 4k, from 700 bytes of actual size).
 */
#ifdef __xtensa__
static void mg_http_handler2(struct mg_connection *nc, int ev, void *ev_data,
                             struct http_message *hm) __attribute__((noinline));

void mg_http_handler(struct mg_connection *nc, int ev, void *ev_data) {
  struct http_message hm;
  mg_http_handler2(nc, ev, ev_data, &hm);
}

static void mg_http_handler2(struct mg_connection *nc, int ev, void *ev_data,
                             struct http_message *hm) {
#else  /* !__XTENSA__ */
void mg_http_handler(struct mg_connection *nc, int ev, void *ev_data) {
  struct http_message shm;
  struct http_message *hm = &shm;
#endif /* __XTENSA__ */
  struct mg_http_proto_data *pd = mg_http_get_proto_data(nc);
  struct mbuf *io = &nc->recv_mbuf;
  int req_len;
  const int is_req = (nc->listener != NULL);
#ifndef MG_DISABLE_HTTP_WEBSOCKET
  struct mg_str *vec;
#endif
  if (ev == MG_EV_CLOSE) {
#ifdef MG_ENABLE_HTTP_STREAMING_MULTIPART
    if (pd->mp_stream.boundary != NULL) {
      /*
       * Multipart message is in progress, but we get close
       * MG_EV_HTTP_PART_END with error flag
       */
      struct mg_http_multipart_part mp;
      memset(&mp, 0, sizeof(mp));

      mp.status = -1;
      mp.var_name = pd->mp_stream.var_name;
      mp.file_name = pd->mp_stream.file_name;
      mg_call(nc, (pd->endpoint_handler ? pd->endpoint_handler : nc->handler),
              MG_EV_HTTP_PART_END, &mp);
    } else
#endif
        if (io->len > 0 && mg_parse_http(io->buf, io->len, hm, is_req) > 0) {
      /*
      * For HTTP messages without Content-Length, always send HTTP message
      * before MG_EV_CLOSE message.
      */
      int ev2 = is_req ? MG_EV_HTTP_REQUEST : MG_EV_HTTP_REPLY;
      hm->message.len = io->len;
      hm->body.len = io->buf + io->len - hm->body.p;
      mg_http_call_endpoint_handler(nc, ev2, hm);
    }
  }

#ifndef MG_DISABLE_FILESYSTEM
  if (pd->file.fp != NULL) {
    mg_http_transfer_file_data(nc);
  }
#endif

  mg_call(nc, nc->handler, ev, ev_data);

  if (ev == MG_EV_RECV) {
    struct mg_str *s;

#ifdef MG_ENABLE_HTTP_STREAMING_MULTIPART
    if (pd->mp_stream.boundary != NULL) {
      mg_http_multipart_continue(nc);
      return;
    }
#endif /* MG_ENABLE_HTTP_STREAMING_MULTIPART */

    req_len = mg_parse_http(io->buf, io->len, hm, is_req);

    if (req_len > 0 &&
        (s = mg_get_http_header(hm, "Transfer-Encoding")) != NULL &&
        mg_vcasecmp(s, "chunked") == 0) {
      mg_handle_chunked(nc, hm, io->buf + req_len, io->len - req_len);
    }

#ifdef MG_ENABLE_HTTP_STREAMING_MULTIPART
    if (req_len > 0 && (s = mg_get_http_header(hm, "Content-Type")) != NULL &&
        s->len >= 9 && strncmp(s->p, "multipart", 9) == 0) {
      mg_http_multipart_begin(nc, hm, req_len);
      mg_http_multipart_continue(nc);
      return;
    }
#endif /* MG_ENABLE_HTTP_STREAMING_MULTIPART */

    /* TODO(alashkin): refactor this ifelseifelseifelseifelse */
    if ((req_len < 0 ||
         (req_len == 0 && io->len >= MG_MAX_HTTP_REQUEST_SIZE))) {
      DBG(("invalid request"));
      nc->flags |= MG_F_CLOSE_IMMEDIATELY;
    } else if (req_len == 0) {
      /* Do nothing, request is not yet fully buffered */
    }
#ifndef MG_DISABLE_HTTP_WEBSOCKET
    else if (nc->listener == NULL &&
             mg_get_http_header(hm, "Sec-WebSocket-Accept")) {
      /* We're websocket client, got handshake response from server. */
      /* TODO(lsm): check the validity of accept Sec-WebSocket-Accept */
      mbuf_remove(io, req_len);
      nc->proto_handler = mg_websocket_handler;
      nc->flags |= MG_F_IS_WEBSOCKET;
      mg_call(nc, nc->handler, MG_EV_WEBSOCKET_HANDSHAKE_DONE, NULL);
      mg_websocket_handler(nc, MG_EV_RECV, ev_data);
    } else if (nc->listener != NULL &&
               (vec = mg_get_http_header(hm, "Sec-WebSocket-Key")) != NULL) {
      /* This is a websocket request. Switch protocol handlers. */
      mbuf_remove(io, req_len);
      nc->proto_handler = mg_websocket_handler;
      nc->flags |= MG_F_IS_WEBSOCKET;

      /* Send handshake */
      mg_call(nc, nc->handler, MG_EV_WEBSOCKET_HANDSHAKE_REQUEST, hm);
      if (!(nc->flags & MG_F_CLOSE_IMMEDIATELY)) {
        if (nc->send_mbuf.len == 0) {
          mg_ws_handshake(nc, vec);
        }
        mg_call(nc, nc->handler, MG_EV_WEBSOCKET_HANDSHAKE_DONE, NULL);
        mg_websocket_handler(nc, MG_EV_RECV, ev_data);
      }
    }
#endif /* MG_DISABLE_HTTP_WEBSOCKET */
    else if (hm->message.len <= io->len) {
      int trigger_ev = nc->listener ? MG_EV_HTTP_REQUEST : MG_EV_HTTP_REPLY;

/* Whole HTTP message is fully buffered, call event handler */

#ifdef MG_ENABLE_JAVASCRIPT
      v7_val_t v1, v2, headers, req, args, res;
      struct v7 *v7 = nc->mgr->v7;
      const char *ev_name = trigger_ev == MG_EV_HTTP_REPLY ? "onsnd" : "onrcv";
      int i, js_callback_handled_request = 0;

      if (v7 != NULL) {
        /* Lookup JS callback */
        v1 = v7_get(v7, v7_get_global(v7), "Http", ~0);
        v2 = v7_get(v7, v1, ev_name, ~0);

        /* Create callback params. TODO(lsm): own/disown those */
        args = v7_mk_array(v7);
        req = v7_mk_object(v7);
        headers = v7_mk_object(v7);

        /* Populate request object */
        v7_set(v7, req, "method", ~0,
               v7_mk_string(v7, hm->method.p, hm->method.len, 1));
        v7_set(v7, req, "uri", ~0, v7_mk_string(v7, hm->uri.p, hm->uri.len, 1));
        v7_set(v7, req, "body", ~0,
               v7_mk_string(v7, hm->body.p, hm->body.len, 1));
        v7_set(v7, req, "headers", ~0, headers);
        for (i = 0; hm->header_names[i].len > 0; i++) {
          const struct mg_str *name = &hm->header_names[i];
          const struct mg_str *value = &hm->header_values[i];
          v7_set(v7, headers, name->p, name->len,
                 v7_mk_string(v7, value->p, value->len, 1));
        }

        /* Invoke callback. TODO(lsm): report errors */
        v7_array_push(v7, args, v7_mk_foreign(v7, nc));
        v7_array_push(v7, args, req);
        if (v7_apply(v7, v2, V7_UNDEFINED, args, &res) == V7_OK &&
            v7_is_truthy(v7, res)) {
          js_callback_handled_request++;
        }
      }

      /* If JS callback returns true, stop request processing */
      if (js_callback_handled_request) {
        nc->flags |= MG_F_SEND_AND_CLOSE;
      } else {
        mg_http_call_endpoint_handler(nc, trigger_ev, hm);
      }
#else
      mg_http_call_endpoint_handler(nc, trigger_ev, hm);
#endif
      mbuf_remove(io, hm->message.len);
    }
  }
  (void) pd;
}

static size_t mg_get_line_len(const char *buf, size_t buf_len) {
  size_t len = 0;
  while (len < buf_len && buf[len] != '\n') len++;
  return len == buf_len ? 0 : len + 1;
}

#ifdef MG_ENABLE_HTTP_STREAMING_MULTIPART
static void mg_http_multipart_begin(struct mg_connection *nc,
                                    struct http_message *hm, int req_len) {
  struct mg_http_proto_data *pd = mg_http_get_proto_data(nc);
  struct mg_str *ct;
  struct mbuf *io = &nc->recv_mbuf;

  char boundary[100];
  int boundary_len;

  if (nc->listener == NULL) {
    /* No streaming for replies now */
    goto exit_mp;
  }

  ct = mg_get_http_header(hm, "Content-Type");
  if (ct == NULL) {
    /* We need more data - or it isn't multipart mesage */
    goto exit_mp;
  }

  /* Content-type should start with "multipart" */
  if (ct->len < 9 || strncmp(ct->p, "multipart", 9) != 0) {
    goto exit_mp;
  }

  boundary_len =
      mg_http_parse_header(ct, "boundary", boundary, sizeof(boundary));
  if (boundary_len == 0) {
    /*
     * Content type is multipart, but there is no boundary,
     * probably malformed request
     */
    nc->flags = MG_F_CLOSE_IMMEDIATELY;
    DBG(("invalid request"));
    goto exit_mp;
  }

  /* If we reach this place - that is multipart request */

  if (pd->mp_stream.boundary != NULL) {
    /*
     * Another streaming request was in progress,
     * looks like protocol error
     */
    nc->flags |= MG_F_CLOSE_IMMEDIATELY;
  } else {
    pd->mp_stream.state = MPS_BEGIN;
    pd->mp_stream.boundary = strdup(boundary);
    pd->mp_stream.boundary_len = strlen(boundary);
    pd->mp_stream.var_name = pd->mp_stream.file_name = NULL;

    pd->endpoint_handler = mg_http_get_endpoint_handler(nc->listener, &hm->uri);
    if (pd->endpoint_handler == NULL) {
      pd->endpoint_handler = nc->handler;
    }

    mg_call(nc, pd->endpoint_handler, MG_EV_HTTP_MULTIPART_REQUEST, hm);

    mbuf_remove(io, req_len);
  }
exit_mp:
  ;
}

#define CONTENT_DISPOSITION "Content-Disposition: "

static void mg_http_multipart_call_handler(struct mg_connection *c, int ev,
                                           const char *data, size_t data_len) {
  struct mg_http_multipart_part mp;
  struct mg_http_proto_data *pd = mg_http_get_proto_data(c);
  memset(&mp, 0, sizeof(mp));

  mp.var_name = pd->mp_stream.var_name;
  mp.file_name = pd->mp_stream.file_name;
  mp.user_data = pd->mp_stream.user_data;
  mp.data.p = data;
  mp.data.len = data_len;
  mg_call(c, pd->endpoint_handler, ev, &mp);
  pd->mp_stream.user_data = mp.user_data;
}

static int mg_http_multipart_got_chunk(struct mg_connection *c) {
  struct mg_http_proto_data *pd = mg_http_get_proto_data(c);
  struct mbuf *io = &c->recv_mbuf;

  mg_http_multipart_call_handler(c, MG_EV_HTTP_PART_DATA, io->buf,
                                 pd->mp_stream.prev_io_len);
  mbuf_remove(io, pd->mp_stream.prev_io_len);
  pd->mp_stream.prev_io_len = 0;
  pd->mp_stream.state = MPS_WAITING_FOR_CHUNK;

  return 0;
}

static int mg_http_multipart_finalize(struct mg_connection *c) {
  struct mg_http_proto_data *pd = mg_http_get_proto_data(c);

  mg_http_multipart_call_handler(c, MG_EV_HTTP_PART_END, NULL, 0);
  mg_http_free_proto_data_mp_stream(&pd->mp_stream);
  pd->mp_stream.state = MPS_FINISHED;

  return 1;
}

static int mg_http_multipart_wait_for_boundary(struct mg_connection *c) {
  const char *boundary;
  struct mbuf *io = &c->recv_mbuf;
  struct mg_http_proto_data *pd = mg_http_get_proto_data(c);

  if ((int) io->len < pd->mp_stream.boundary_len + 2) {
    return 0;
  }

  boundary = c_strnstr(io->buf, pd->mp_stream.boundary, io->len);
  if (boundary != NULL) {
    if (io->len - (boundary - io->buf) < 4) {
      return 0;
    }
    if (memcmp(boundary + pd->mp_stream.boundary_len, "--", 2) == 0) {
      pd->mp_stream.state = MPS_FINALIZE;
    } else {
      pd->mp_stream.state = MPS_GOT_BOUNDARY;
    }
  } else {
    return 0;
  }

  return 1;
}

static int mg_http_multipart_process_boundary(struct mg_connection *c) {
  int data_size;
  const char *boundary, *block_begin;
  struct mbuf *io = &c->recv_mbuf;
  struct mg_http_proto_data *pd = mg_http_get_proto_data(c);
  char file_name[100], var_name[100];
  int line_len;
  boundary = c_strnstr(io->buf, pd->mp_stream.boundary, io->len);
  block_begin = boundary + pd->mp_stream.boundary_len + 2;
  data_size = io->len - (block_begin - io->buf);

  while (data_size > 0 &&
         (line_len = mg_get_line_len(block_begin, data_size)) != 0) {
    if (line_len > (int) sizeof(CONTENT_DISPOSITION) &&
        mg_ncasecmp(block_begin, CONTENT_DISPOSITION,
                    sizeof(CONTENT_DISPOSITION) - 1) == 0) {
      struct mg_str header;

      header.p = block_begin + sizeof(CONTENT_DISPOSITION) - 1;
      header.len = line_len - sizeof(CONTENT_DISPOSITION) - 1;
      mg_http_parse_header(&header, "name", var_name, sizeof(var_name) - 2);
      mg_http_parse_header(&header, "filename", file_name,
                           sizeof(file_name) - 2);
      block_begin += line_len;
      data_size -= line_len;
      continue;
    }

    if (line_len == 2 && mg_ncasecmp(block_begin, "\r\n", 2) == 0) {
      mbuf_remove(io, block_begin - io->buf + 2);

      if (pd->mp_stream.processing_part != 0) {
        mg_http_multipart_call_handler(c, MG_EV_HTTP_PART_END, NULL, 0);
      }

      free((void *) pd->mp_stream.file_name);
      pd->mp_stream.file_name = strdup(file_name);
      free((void *) pd->mp_stream.var_name);
      pd->mp_stream.var_name = strdup(var_name);

      mg_http_multipart_call_handler(c, MG_EV_HTTP_PART_BEGIN, NULL, 0);
      pd->mp_stream.state = MPS_WAITING_FOR_CHUNK;
      pd->mp_stream.processing_part++;
      return 1;
    }

    block_begin += line_len;
  }

  pd->mp_stream.state = MPS_WAITING_FOR_BOUNDARY;

  return 0;
}

static int mg_http_multipart_continue_wait_for_chunk(struct mg_connection *c) {
  struct mg_http_proto_data *pd = mg_http_get_proto_data(c);
  struct mbuf *io = &c->recv_mbuf;

  const char *boundary;
  if ((int) io->len < pd->mp_stream.boundary_len + 6 /* \r\n, --, -- */) {
    return 0;
  }

  boundary = c_strnstr(io->buf, pd->mp_stream.boundary, io->len);
  if (boundary == NULL && pd->mp_stream.prev_io_len == 0) {
    pd->mp_stream.prev_io_len = io->len;
    return 0;
  } else if (boundary == NULL &&
             (int) io->len >
                 pd->mp_stream.prev_io_len + pd->mp_stream.boundary_len + 4) {
    pd->mp_stream.state = MPS_GOT_CHUNK;
    return 1;
  } else if (boundary != NULL) {
    int data_size = (boundary - io->buf - 4);
    mg_http_multipart_call_handler(c, MG_EV_HTTP_PART_DATA, io->buf, data_size);
    mbuf_remove(io, (boundary - io->buf));
    pd->mp_stream.prev_io_len = 0;
    pd->mp_stream.state = MPS_WAITING_FOR_BOUNDARY;
    return 1;
  } else {
    return 0;
  }
}

static void mg_http_multipart_continue(struct mg_connection *c) {
  struct mg_http_proto_data *pd = mg_http_get_proto_data(c);
  while (1) {
    switch (pd->mp_stream.state) {
      case MPS_BEGIN: {
        pd->mp_stream.state = MPS_WAITING_FOR_BOUNDARY;
        break;
      }
      case MPS_WAITING_FOR_BOUNDARY: {
        if (mg_http_multipart_wait_for_boundary(c) == 0) {
          return;
        }
        break;
      }
      case MPS_GOT_BOUNDARY: {
        if (mg_http_multipart_process_boundary(c) == 0) {
          return;
        }
        break;
      }
      case MPS_WAITING_FOR_CHUNK: {
        if (mg_http_multipart_continue_wait_for_chunk(c) == 0) {
          return;
        }
        break;
      }
      case MPS_GOT_CHUNK: {
        if (mg_http_multipart_got_chunk(c) == 0) {
          return;
        }
        break;
      }
      case MPS_FINALIZE: {
        if (mg_http_multipart_finalize(c) == 0) {
          return;
        }
        break;
      }
      case MPS_FINISHED: {
        mbuf_remove(&c->recv_mbuf, c->recv_mbuf.len);
        return;
      }
    }
  }
}

struct file_upload_state {
  char *lfn;
  size_t num_recd;
  FILE *fp;
};

void mg_file_upload_handler(struct mg_connection *nc, int ev, void *ev_data,
                            mg_fu_fname_fn local_name_fn) {
  switch (ev) {
    case MG_EV_HTTP_PART_BEGIN: {
      struct mg_http_multipart_part *mp =
          (struct mg_http_multipart_part *) ev_data;
      struct file_upload_state *fus =
          (struct file_upload_state *) calloc(1, sizeof(*fus));
      mp->user_data = NULL;

      struct mg_str lfn = local_name_fn(nc, mg_mk_str(mp->file_name));
      if (lfn.p == NULL || lfn.len == 0) {
        LOG(LL_ERROR, ("%p Not allowed to upload %s", nc, mp->file_name));
        mg_printf(nc,
                  "HTTP/1.1 403 Not Allowed\r\n"
                  "Content-Type: text/plain\r\n"
                  "Connection: close\r\n\r\n"
                  "Not allowed to upload %s\r\n",
                  mp->file_name);
        nc->flags |= MG_F_SEND_AND_CLOSE;
        return;
      }
      fus->lfn = (char *) malloc(lfn.len + 1);
      memcpy(fus->lfn, lfn.p, lfn.len);
      fus->lfn[lfn.len] = '\0';
      if (lfn.p != mp->file_name) free((char *) lfn.p);
      LOG(LL_DEBUG,
          ("%p Receiving file %s -> %s", nc, mp->file_name, fus->lfn));
      fus->fp = fopen(fus->lfn, "w");
      if (fus->fp == NULL) {
        mg_printf(nc,
                  "HTTP/1.1 500 Internal Server Error\r\n"
                  "Content-Type: text/plain\r\n"
                  "Connection: close\r\n\r\n");
        LOG(LL_ERROR, ("Failed to open %s: %d\n", fus->lfn, errno));
        mg_printf(nc, "Failed to open %s: %d\n", fus->lfn, errno);
        /* Do not close the connection just yet, discard remainder of the data.
         * This is because at the time of writing some browsers (Chrome) fail to
         * render response before all the data is sent. */
      }
      mp->user_data = (void *) fus;
      break;
    }
    case MG_EV_HTTP_PART_DATA: {
      struct mg_http_multipart_part *mp =
          (struct mg_http_multipart_part *) ev_data;
      struct file_upload_state *fus =
          (struct file_upload_state *) mp->user_data;
      if (fus == NULL || fus->fp == NULL) break;
      if (fwrite(mp->data.p, 1, mp->data.len, fus->fp) != mp->data.len) {
        LOG(LL_ERROR, ("Failed to write to %s: %d, wrote %d", fus->lfn, errno,
                       (int) fus->num_recd));
        if (errno == ENOSPC
#ifdef SPIFFS_ERR_FULL
            || errno == SPIFFS_ERR_FULL
#endif
            ) {
          mg_printf(nc,
                    "HTTP/1.1 413 Payload Too Large\r\n"
                    "Content-Type: text/plain\r\n"
                    "Connection: close\r\n\r\n");
          mg_printf(nc, "Failed to write to %s: no space left; wrote %d\r\n",
                    fus->lfn, (int) fus->num_recd);
        } else {
          mg_printf(nc,
                    "HTTP/1.1 500 Internal Server Error\r\n"
                    "Content-Type: text/plain\r\n"
                    "Connection: close\r\n\r\n");
          mg_printf(nc, "Failed to write to %s: %d, wrote %d", mp->file_name,
                    errno, (int) fus->num_recd);
        }
        fclose(fus->fp);
        remove(fus->lfn);
        fus->fp = NULL;
        /* Do not close the connection just yet, discard remainder of the data.
         * This is because at the time of writing some browsers (Chrome) fail to
         * render response before all the data is sent. */
        return;
      }
      fus->num_recd += mp->data.len;
      LOG(LL_DEBUG, ("%p rec'd %d bytes, %d total", nc, (int) mp->data.len,
                     (int) fus->num_recd));
      break;
    }
    case MG_EV_HTTP_PART_END: {
      struct mg_http_multipart_part *mp =
          (struct mg_http_multipart_part *) ev_data;
      struct file_upload_state *fus =
          (struct file_upload_state *) mp->user_data;
      if (fus == NULL) break;
      if (mp->status >= 0 && fus->fp != NULL) {
        LOG(LL_DEBUG, ("%p Uploaded %s (%s), %d bytes", nc, mp->file_name,
                       fus->lfn, (int) fus->num_recd));
        mg_printf(nc,
                  "HTTP/1.1 200 OK\r\n"
                  "Content-Type: text/plain\r\n"
                  "Connection: close\r\n\r\n"
                  "Ok, %s - %d bytes.\r\n",
                  mp->file_name, (int) fus->num_recd);
      } else {
        LOG(LL_ERROR, ("Failed to store %s (%s)", mp->file_name, fus->lfn));
        /*
         * mp->status < 0 means connection was terminated, so no reason to send
         * HTTP reply
         */
      }
      if (fus->fp != NULL) fclose(fus->fp);
      free(fus->lfn);
      free(fus);
      mp->user_data = NULL;
      nc->flags |= MG_F_SEND_AND_CLOSE;
      break;
    }
  }
}

#endif /* MG_ENABLE_HTTP_STREAMING_MULTIPART */

void mg_set_protocol_http_websocket(struct mg_connection *nc) {
  nc->proto_handler = mg_http_handler;
}

#ifndef MG_DISABLE_HTTP_WEBSOCKET

void mg_send_websocket_handshake2(struct mg_connection *nc, const char *path,
                                  const char *host, const char *protocol,
                                  const char *extra_headers) {
  char key[25];
  uint32_t nonce[4];
  nonce[0] = mg_ws_random_mask();
  nonce[1] = mg_ws_random_mask();
  nonce[2] = mg_ws_random_mask();
  nonce[3] = mg_ws_random_mask();
  mg_base64_encode((unsigned char *) &nonce, sizeof(nonce), key);

  mg_printf(nc,
            "GET %s HTTP/1.1\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Sec-WebSocket-Key: %s\r\n",
            path, key);

  /* TODO(mkm): take default hostname from http proto data if host == NULL */
  if (host != MG_WS_NO_HOST_HEADER_MAGIC) {
    mg_printf(nc, "Host: %s\r\n", host);
  }
  if (protocol != NULL) {
    mg_printf(nc, "Sec-WebSocket-Protocol: %s\r\n", protocol);
  }
  if (extra_headers != NULL) {
    mg_printf(nc, "%s", extra_headers);
  }
  mg_printf(nc, "\r\n");
}

void mg_send_websocket_handshake(struct mg_connection *nc, const char *path,
                                 const char *extra_headers) {
  mg_send_websocket_handshake2(nc, path, MG_WS_NO_HOST_HEADER_MAGIC, NULL,
                               extra_headers);
}

#endif /* MG_DISABLE_HTTP_WEBSOCKET */

void mg_send_response_line_s(struct mg_connection *nc, int status_code,
                             const struct mg_str extra_headers) {
  const char *status_message = "OK";
  switch (status_code) {
    case 206:
      status_message = "Partial Content";
      break;
    case 301:
      status_message = "Moved";
      break;
    case 302:
      status_message = "Found";
      break;
    case 401:
      status_message = "Unauthorized";
      break;
    case 403:
      status_message = "Forbidden";
      break;
    case 404:
      status_message = "Not Found";
      break;
    case 416:
      status_message = "Requested range not satisfiable";
      break;
    case 418:
      status_message = "I'm a teapot";
      break;
    case 500:
      status_message = "Internal Server Error";
      break;
  }
  mg_printf(nc, "HTTP/1.1 %d %s\r\nServer: %s\r\n", status_code, status_message,
            mg_version_header);
  if (extra_headers.len > 0) {
    mg_printf(nc, "%.*s\r\n", (int) extra_headers.len, extra_headers.p);
  }
}

void mg_send_response_line(struct mg_connection *nc, int status_code,
                           const char *extra_headers) {
  mg_send_response_line_s(nc, status_code, mg_mk_str(extra_headers));
}

void mg_send_head(struct mg_connection *c, int status_code,
                  int64_t content_length, const char *extra_headers) {
  mg_send_response_line(c, status_code, extra_headers);
  if (content_length < 0) {
    mg_printf(c, "%s", "Transfer-Encoding: chunked\r\n");
  } else {
    mg_printf(c, "Content-Length: %" INT64_FMT "\r\n", content_length);
  }
  mg_send(c, "\r\n", 2);
}

#ifdef MG_DISABLE_FILESYSTEM
void mg_serve_http(struct mg_connection *nc, struct http_message *hm,
                   struct mg_serve_http_opts opts) {
  mg_send_head(nc, 501, 0, NULL);
}
#else
static void mg_http_send_error(struct mg_connection *nc, int code,
                               const char *reason) {
  if (!reason) reason = "";
  DBG(("%p %d %s", nc, code, reason));
  mg_send_head(nc, code, strlen(reason),
               "Content-Type: text/plain\r\nConnection: close");
  mg_send(nc, reason, strlen(reason));
  nc->flags |= MG_F_SEND_AND_CLOSE;
}
#ifndef MG_DISABLE_SSI
static void mg_send_ssi_file(struct mg_connection *, const char *, FILE *, int,
                             const struct mg_serve_http_opts *);

static void mg_send_file_data(struct mg_connection *nc, FILE *fp) {
  char buf[BUFSIZ];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
    mg_send(nc, buf, n);
  }
}

static void mg_do_ssi_include(struct mg_connection *nc, const char *ssi,
                              char *tag, int include_level,
                              const struct mg_serve_http_opts *opts) {
  char file_name[BUFSIZ], path[MAX_PATH_SIZE], *p;
  FILE *fp;

  /*
   * sscanf() is safe here, since send_ssi_file() also uses buffer
   * of size MG_BUF_LEN to get the tag. So strlen(tag) is always < MG_BUF_LEN.
   */
  if (sscanf(tag, " virtual=\"%[^\"]\"", file_name) == 1) {
    /* File name is relative to the webserver root */
    snprintf(path, sizeof(path), "%s/%s", opts->document_root, file_name);
  } else if (sscanf(tag, " abspath=\"%[^\"]\"", file_name) == 1) {
    /*
     * File name is relative to the webserver working directory
     * or it is absolute system path
     */
    snprintf(path, sizeof(path), "%s", file_name);
  } else if (sscanf(tag, " file=\"%[^\"]\"", file_name) == 1 ||
             sscanf(tag, " \"%[^\"]\"", file_name) == 1) {
    /* File name is relative to the currect document */
    snprintf(path, sizeof(path), "%s", ssi);
    if ((p = strrchr(path, DIRSEP)) != NULL) {
      p[1] = '\0';
    }
    snprintf(path + strlen(path), sizeof(path) - strlen(path), "%s", file_name);
  } else {
    mg_printf(nc, "Bad SSI #include: [%s]", tag);
    return;
  }

  if ((fp = fopen(path, "rb")) == NULL) {
    mg_printf(nc, "SSI include error: fopen(%s): %s", path, strerror(errno));
  } else {
    mg_set_close_on_exec(fileno(fp));
    if (mg_match_prefix(opts->ssi_pattern, strlen(opts->ssi_pattern), path) >
        0) {
      mg_send_ssi_file(nc, path, fp, include_level + 1, opts);
    } else {
      mg_send_file_data(nc, fp);
    }
    fclose(fp);
  }
}

#ifndef MG_DISABLE_POPEN
static void do_ssi_exec(struct mg_connection *nc, char *tag) {
  char cmd[BUFSIZ];
  FILE *fp;

  if (sscanf(tag, " \"%[^\"]\"", cmd) != 1) {
    mg_printf(nc, "Bad SSI #exec: [%s]", tag);
  } else if ((fp = popen(cmd, "r")) == NULL) {
    mg_printf(nc, "Cannot SSI #exec: [%s]: %s", cmd, strerror(errno));
  } else {
    mg_send_file_data(nc, fp);
    pclose(fp);
  }
}
#endif /* !MG_DISABLE_POPEN */

static void mg_do_ssi_call(struct mg_connection *nc, char *tag) {
  mg_call(nc, NULL, MG_EV_SSI_CALL, tag);
}

/*
 * SSI directive has the following format:
 * <!--#directive parameter=value parameter=value -->
 */
static void mg_send_ssi_file(struct mg_connection *nc, const char *path,
                             FILE *fp, int include_level,
                             const struct mg_serve_http_opts *opts) {
  static const struct mg_str btag = MG_MK_STR("<!--#");
  static const struct mg_str d_include = MG_MK_STR("include");
  static const struct mg_str d_call = MG_MK_STR("call");
#ifndef MG_DISABLE_POPEN
  static const struct mg_str d_exec = MG_MK_STR("exec");
#endif
  char buf[BUFSIZ], *p = buf + btag.len; /* p points to SSI directive */
  int ch, len, in_ssi_tag;

  if (include_level > 10) {
    mg_printf(nc, "SSI #include level is too deep (%s)", path);
    return;
  }

  in_ssi_tag = len = 0;
  while ((ch = fgetc(fp)) != EOF) {
    if (in_ssi_tag && ch == '>' && buf[len - 1] == '-' && buf[len - 2] == '-') {
      size_t i = len - 2;
      in_ssi_tag = 0;

      /* Trim closing --> */
      buf[i--] = '\0';
      while (i > 0 && buf[i] == ' ') {
        buf[i--] = '\0';
      }

      /* Handle known SSI directives */
      if (memcmp(p, d_include.p, d_include.len) == 0) {
        mg_do_ssi_include(nc, path, p + d_include.len + 1, include_level, opts);
      } else if (memcmp(p, d_call.p, d_call.len) == 0) {
        mg_do_ssi_call(nc, p + d_call.len + 1);
#ifndef MG_DISABLE_POPEN
      } else if (memcmp(p, d_exec.p, d_exec.len) == 0) {
        do_ssi_exec(nc, p + d_exec.len + 1);
#endif
      } else {
        /* Silently ignore unknown SSI directive. */
      }
      len = 0;
    } else if (ch == '<') {
      in_ssi_tag = 1;
      if (len > 0) {
        mg_send(nc, buf, (size_t) len);
      }
      len = 0;
      buf[len++] = ch & 0xff;
    } else if (in_ssi_tag) {
      if (len == (int) btag.len && memcmp(buf, btag.p, btag.len) != 0) {
        /* Not an SSI tag */
        in_ssi_tag = 0;
      } else if (len == (int) sizeof(buf) - 2) {
        mg_printf(nc, "%s: SSI tag is too large", path);
        len = 0;
      }
      buf[len++] = ch & 0xff;
    } else {
      buf[len++] = ch & 0xff;
      if (len == (int) sizeof(buf)) {
        mg_send(nc, buf, (size_t) len);
        len = 0;
      }
    }
  }

  /* Send the rest of buffered data */
  if (len > 0) {
    mg_send(nc, buf, (size_t) len);
  }
}

static void mg_handle_ssi_request(struct mg_connection *nc, const char *path,
                                  const struct mg_serve_http_opts *opts) {
  FILE *fp;
  struct mg_str mime_type;
  DBG(("%p %s", nc, path));

  if ((fp = fopen(path, "rb")) == NULL) {
    mg_http_send_error(nc, 404, NULL);
  } else {
    mg_set_close_on_exec(fileno(fp));

    mime_type = mg_get_mime_type(path, "text/plain", opts);
    mg_send_response_line(nc, 200, opts->extra_headers);
    mg_printf(nc,
              "Content-Type: %.*s\r\n"
              "Connection: close\r\n\r\n",
              (int) mime_type.len, mime_type.p);
    mg_send_ssi_file(nc, path, fp, 0, opts);
    fclose(fp);
    nc->flags |= MG_F_SEND_AND_CLOSE;
  }
}
#else
static void mg_handle_ssi_request(struct mg_connection *nc, const char *path,
                                  const struct mg_serve_http_opts *opts) {
  (void) path;
  (void) opts;
  mg_http_send_error(nc, 500, "SSI disabled");
}
#endif /* MG_DISABLE_SSI */

static void mg_http_construct_etag(char *buf, size_t buf_len,
                                   const cs_stat_t *st) {
  snprintf(buf, buf_len, "\"%lx.%" INT64_FMT "\"", (unsigned long) st->st_mtime,
           (int64_t) st->st_size);
}
static void mg_gmt_time_string(char *buf, size_t buf_len, time_t *t) {
  strftime(buf, buf_len, "%a, %d %b %Y %H:%M:%S GMT", gmtime(t));
}

static int mg_http_parse_range_header(const struct mg_str *header, int64_t *a,
                                      int64_t *b) {
  /*
   * There is no snscanf. Headers are not guaranteed to be NUL-terminated,
   * so we have this. Ugh.
   */
  int result;
  char *p = (char *) MG_MALLOC(header->len + 1);
  if (p == NULL) return 0;
  memcpy(p, header->p, header->len);
  p[header->len] = '\0';
  result = sscanf(p, "bytes=%" INT64_FMT "-%" INT64_FMT, a, b);
  MG_FREE(p);
  return result;
}

void mg_http_serve_file(struct mg_connection *nc, struct http_message *hm,
                        const char *path, const struct mg_str mime_type,
                        const struct mg_str extra_headers) {
  struct mg_http_proto_data *pd = mg_http_get_proto_data(nc);
  cs_stat_t st;
  DBG(("%p [%s] %.*s", nc, path, (int) mime_type.len, mime_type.p));
  if (mg_stat(path, &st) != 0 || (pd->file.fp = fopen(path, "rb")) == NULL) {
    int code;
    switch (errno) {
      case EACCES:
        code = 403;
        break;
      case ENOENT:
        code = 404;
        break;
      default:
        code = 500;
    };
    mg_http_send_error(nc, code, "Open failed");
  } else {
    char etag[50], current_time[50], last_modified[50], range[70];
    time_t t = time(NULL);
    int64_t r1 = 0, r2 = 0, cl = st.st_size;
    struct mg_str *range_hdr = mg_get_http_header(hm, "Range");
    int n, status_code = 200;

    /* Handle Range header */
    range[0] = '\0';
    if (range_hdr != NULL &&
        (n = mg_http_parse_range_header(range_hdr, &r1, &r2)) > 0 && r1 >= 0 &&
        r2 >= 0) {
      /* If range is specified like "400-", set second limit to content len */
      if (n == 1) {
        r2 = cl - 1;
      }
      if (r1 > r2 || r2 >= cl) {
        status_code = 416;
        cl = 0;
        snprintf(range, sizeof(range),
                 "Content-Range: bytes */%" INT64_FMT "\r\n",
                 (int64_t) st.st_size);
      } else {
        status_code = 206;
        cl = r2 - r1 + 1;
        snprintf(range, sizeof(range), "Content-Range: bytes %" INT64_FMT
                                       "-%" INT64_FMT "/%" INT64_FMT "\r\n",
                 r1, r1 + cl - 1, (int64_t) st.st_size);
#if _FILE_OFFSET_BITS == 64 || _POSIX_C_SOURCE >= 200112L || \
    _XOPEN_SOURCE >= 600
        fseeko(pd->file.fp, r1, SEEK_SET);
#else
        fseek(pd->file.fp, (long) r1, SEEK_SET);
#endif
      }
    }

#ifndef MG_DISABLE_HTTP_KEEP_ALIVE
    {
      struct mg_str *conn_hdr = mg_get_http_header(hm, "Connection");
      if (conn_hdr != NULL) {
        pd->file.keepalive = (mg_vcasecmp(conn_hdr, "keep-alive") == 0);
      } else {
        pd->file.keepalive = (mg_vcmp(&hm->proto, "HTTP/1.1") == 0);
      }
    }
#endif

    mg_http_construct_etag(etag, sizeof(etag), &st);
    mg_gmt_time_string(current_time, sizeof(current_time), &t);
    mg_gmt_time_string(last_modified, sizeof(last_modified), &st.st_mtime);
    /*
     * Content length casted to size_t because:
     * 1) that's the maximum buffer size anyway
     * 2) ESP8266 RTOS SDK newlib vprintf cannot contain a 64bit arg at non-last
     *    position
     * TODO(mkm): fix ESP8266 RTOS SDK
     */
    mg_send_response_line_s(nc, status_code, extra_headers);
    mg_printf(nc,
              "Date: %s\r\n"
              "Last-Modified: %s\r\n"
              "Accept-Ranges: bytes\r\n"
              "Content-Type: %.*s\r\n"
              "Connection: %s\r\n"
              "Content-Length: %" SIZE_T_FMT
              "\r\n"
              "%sEtag: %s\r\n\r\n",
              current_time, last_modified, (int) mime_type.len, mime_type.p,
              (pd->file.keepalive ? "keep-alive" : "close"), (size_t) cl, range,
              etag);

    pd->file.cl = cl;
    pd->file.type = DATA_FILE;
    mg_http_transfer_file_data(nc);
  }
}

static void mg_http_serve_file2(struct mg_connection *nc, const char *path,
                                struct http_message *hm,
                                struct mg_serve_http_opts *opts) {
  if (mg_match_prefix(opts->ssi_pattern, strlen(opts->ssi_pattern), path) > 0) {
    mg_handle_ssi_request(nc, path, opts);
    return;
  }
  mg_http_serve_file(nc, hm, path, mg_get_mime_type(path, "text/plain", opts),
                     mg_mk_str(opts->extra_headers));
}

#endif

int mg_url_decode(const char *src, int src_len, char *dst, int dst_len,
                  int is_form_url_encoded) {
  int i, j, a, b;
#define HEXTOI(x) (isdigit(x) ? x - '0' : x - 'W')

  for (i = j = 0; i < src_len && j < dst_len - 1; i++, j++) {
    if (src[i] == '%') {
      if (i < src_len - 2 && isxdigit(*(const unsigned char *) (src + i + 1)) &&
          isxdigit(*(const unsigned char *) (src + i + 2))) {
        a = tolower(*(const unsigned char *) (src + i + 1));
        b = tolower(*(const unsigned char *) (src + i + 2));
        dst[j] = (char) ((HEXTOI(a) << 4) | HEXTOI(b));
        i += 2;
      } else {
        return -1;
      }
    } else if (is_form_url_encoded && src[i] == '+') {
      dst[j] = ' ';
    } else {
      dst[j] = src[i];
    }
  }

  dst[j] = '\0'; /* Null-terminate the destination */

  return i >= src_len ? j : -1;
}

int mg_get_http_var(const struct mg_str *buf, const char *name, char *dst,
                    size_t dst_len) {
  const char *p, *e, *s;
  size_t name_len;
  int len;

  if (dst == NULL || dst_len == 0) {
    len = -2;
  } else if (buf->p == NULL || name == NULL || buf->len == 0) {
    len = -1;
    dst[0] = '\0';
  } else {
    name_len = strlen(name);
    e = buf->p + buf->len;
    len = -1;
    dst[0] = '\0';

    for (p = buf->p; p + name_len < e; p++) {
      if ((p == buf->p || p[-1] == '&') && p[name_len] == '=' &&
          !mg_ncasecmp(name, p, name_len)) {
        p += name_len + 1;
        s = (const char *) memchr(p, '&', (size_t)(e - p));
        if (s == NULL) {
          s = e;
        }
        len = mg_url_decode(p, (size_t)(s - p), dst, dst_len, 1);
        if (len == -1) {
          len = -2;
        }
        break;
      }
    }
  }

  return len;
}

void mg_send_http_chunk(struct mg_connection *nc, const char *buf, size_t len) {
  char chunk_size[50];
  int n;

  n = snprintf(chunk_size, sizeof(chunk_size), "%lX\r\n", (unsigned long) len);
  mg_send(nc, chunk_size, n);
  mg_send(nc, buf, len);
  mg_send(nc, "\r\n", 2);
}

void mg_printf_http_chunk(struct mg_connection *nc, const char *fmt, ...) {
  char mem[MG_VPRINTF_BUFFER_SIZE], *buf = mem;
  int len;
  va_list ap;

  va_start(ap, fmt);
  len = mg_avprintf(&buf, sizeof(mem), fmt, ap);
  va_end(ap);

  if (len >= 0) {
    mg_send_http_chunk(nc, buf, len);
  }

  /* LCOV_EXCL_START */
  if (buf != mem && buf != NULL) {
    MG_FREE(buf);
  }
  /* LCOV_EXCL_STOP */
}

void mg_printf_html_escape(struct mg_connection *nc, const char *fmt, ...) {
  char mem[MG_VPRINTF_BUFFER_SIZE], *buf = mem;
  int i, j, len;
  va_list ap;

  va_start(ap, fmt);
  len = mg_avprintf(&buf, sizeof(mem), fmt, ap);
  va_end(ap);

  if (len >= 0) {
    for (i = j = 0; i < len; i++) {
      if (buf[i] == '<' || buf[i] == '>') {
        mg_send(nc, buf + j, i - j);
        mg_send(nc, buf[i] == '<' ? "&lt;" : "&gt;", 4);
        j = i + 1;
      }
    }
    mg_send(nc, buf + j, i - j);
  }

  /* LCOV_EXCL_START */
  if (buf != mem && buf != NULL) {
    MG_FREE(buf);
  }
  /* LCOV_EXCL_STOP */
}

int mg_http_parse_header(struct mg_str *hdr, const char *var_name, char *buf,
                         size_t buf_size) {
  int ch = ' ', ch1 = ',', len = 0, n = strlen(var_name);
  const char *p, *end = hdr ? hdr->p + hdr->len : NULL, *s = NULL;

  if (buf != NULL && buf_size > 0) buf[0] = '\0';
  if (hdr == NULL) return 0;

  /* Find where variable starts */
  for (s = hdr->p; s != NULL && s + n < end; s++) {
    if ((s == hdr->p || s[-1] == ch || s[-1] == ch1) && s[n] == '=' &&
        !memcmp(s, var_name, n))
      break;
  }

  if (s != NULL && &s[n + 1] < end) {
    s += n + 1;
    if (*s == '"' || *s == '\'') {
      ch = ch1 = *s++;
    }
    p = s;
    while (p < end && p[0] != ch && p[0] != ch1 && len < (int) buf_size) {
      if (ch != ' ' && p[0] == '\\' && p[1] == ch) p++;
      buf[len++] = *p++;
    }
    if (len >= (int) buf_size || (ch != ' ' && *p != ch)) {
      len = 0;
    } else {
      if (len > 0 && s[len - 1] == ',') len--;
      if (len > 0 && s[len - 1] == ';') len--;
      buf[len] = '\0';
    }
  }

  return len;
}

#ifndef MG_DISABLE_FILESYSTEM
static int mg_is_file_hidden(const char *path,
                             const struct mg_serve_http_opts *opts,
                             int exclude_specials) {
  const char *p1 = opts->per_directory_auth_file;
  const char *p2 = opts->hidden_file_pattern;

  /* Strip directory path from the file name */
  const char *pdir = strrchr(path, DIRSEP);
  if (pdir != NULL) {
    path = pdir + 1;
  }

  return (exclude_specials && (!strcmp(path, ".") || !strcmp(path, ".."))) ||
         (p1 != NULL &&
          mg_match_prefix(p1, strlen(p1), path) == (int) strlen(p1)) ||
         (p2 != NULL && mg_match_prefix(p2, strlen(p2), path) > 0);
}

#ifndef MG_DISABLE_HTTP_DIGEST_AUTH
static void mg_mkmd5resp(const char *method, size_t method_len, const char *uri,
                         size_t uri_len, const char *ha1, size_t ha1_len,
                         const char *nonce, size_t nonce_len, const char *nc,
                         size_t nc_len, const char *cnonce, size_t cnonce_len,
                         const char *qop, size_t qop_len, char *resp) {
  static const char colon[] = ":";
  static const size_t one = 1;
  char ha2[33];

  cs_md5(ha2, method, method_len, colon, one, uri, uri_len, NULL);
  cs_md5(resp, ha1, ha1_len, colon, one, nonce, nonce_len, colon, one, nc,
         nc_len, colon, one, cnonce, cnonce_len, colon, one, qop, qop_len,
         colon, one, ha2, sizeof(ha2) - 1, NULL);
}

int mg_http_create_digest_auth_header(char *buf, size_t buf_len,
                                      const char *method, const char *uri,
                                      const char *auth_domain, const char *user,
                                      const char *passwd) {
  static const char colon[] = ":", qop[] = "auth";
  static const size_t one = 1;
  char ha1[33], resp[33], cnonce[40];

  snprintf(cnonce, sizeof(cnonce), "%x", (unsigned int) time(NULL));
  cs_md5(ha1, user, (size_t) strlen(user), colon, one, auth_domain,
         (size_t) strlen(auth_domain), colon, one, passwd,
         (size_t) strlen(passwd), NULL);
  mg_mkmd5resp(method, strlen(method), uri, strlen(uri), ha1, sizeof(ha1) - 1,
               cnonce, strlen(cnonce), "1", one, cnonce, strlen(cnonce), qop,
               sizeof(qop) - 1, resp);
  return snprintf(buf, buf_len,
                  "Authorization: Digest username=\"%s\","
                  "realm=\"%s\",uri=\"%s\",qop=%s,nc=1,cnonce=%s,"
                  "nonce=%s,response=%s\r\n",
                  user, auth_domain, uri, qop, cnonce, cnonce, resp);
}

/*
 * Check for authentication timeout.
 * Clients send time stamp encoded in nonce. Make sure it is not too old,
 * to prevent replay attacks.
 * Assumption: nonce is a hexadecimal number of seconds since 1970.
 */
static int mg_check_nonce(const char *nonce) {
  unsigned long now = (unsigned long) time(NULL);
  unsigned long val = (unsigned long) strtoul(nonce, NULL, 16);
  return now < val || now - val < 3600;
}

int mg_http_check_digest_auth(struct http_message *hm, const char *auth_domain,
                              FILE *fp) {
  struct mg_str *hdr;
  char buf[128], f_user[sizeof(buf)], f_ha1[sizeof(buf)], f_domain[sizeof(buf)];
  char user[50], cnonce[33], response[40], uri[200], qop[20], nc[20], nonce[30];
  char expected_response[33];

  /* Parse "Authorization:" header, fail fast on parse error */
  if (hm == NULL || fp == NULL ||
      (hdr = mg_get_http_header(hm, "Authorization")) == NULL ||
      mg_http_parse_header(hdr, "username", user, sizeof(user)) == 0 ||
      mg_http_parse_header(hdr, "cnonce", cnonce, sizeof(cnonce)) == 0 ||
      mg_http_parse_header(hdr, "response", response, sizeof(response)) == 0 ||
      mg_http_parse_header(hdr, "uri", uri, sizeof(uri)) == 0 ||
      mg_http_parse_header(hdr, "qop", qop, sizeof(qop)) == 0 ||
      mg_http_parse_header(hdr, "nc", nc, sizeof(nc)) == 0 ||
      mg_http_parse_header(hdr, "nonce", nonce, sizeof(nonce)) == 0 ||
      mg_check_nonce(nonce) == 0) {
    return 0;
  }

  /*
   * Read passwords file line by line. If should have htdigest format,
   * i.e. each line should be a colon-separated sequence:
   * USER_NAME:DOMAIN_NAME:HA1_HASH_OF_USER_DOMAIN_AND_PASSWORD
   */
  while (fgets(buf, sizeof(buf), fp) != NULL) {
    if (sscanf(buf, "%[^:]:%[^:]:%s", f_user, f_domain, f_ha1) == 3 &&
        strcmp(user, f_user) == 0 &&
        /* NOTE(lsm): due to a bug in MSIE, we do not compare URIs */
        strcmp(auth_domain, f_domain) == 0) {
      /* User and domain matched, check the password */
      mg_mkmd5resp(
          hm->method.p, hm->method.len, hm->uri.p,
          hm->uri.len + (hm->query_string.len ? hm->query_string.len + 1 : 0),
          f_ha1, strlen(f_ha1), nonce, strlen(nonce), nc, strlen(nc), cnonce,
          strlen(cnonce), qop, strlen(qop), expected_response);
      return mg_casecmp(response, expected_response) == 0;
    }
  }

  /* None of the entries in the passwords file matched - return failure */
  return 0;
}

static int mg_is_authorized(struct http_message *hm, const char *path,
                            int is_directory, const char *domain,
                            const char *passwords_file,
                            int is_global_pass_file) {
  char buf[MG_MAX_PATH];
  const char *p;
  FILE *fp;
  int authorized = 1;

  if (domain != NULL && passwords_file != NULL) {
    if (is_global_pass_file) {
      fp = fopen(passwords_file, "r");
    } else if (is_directory) {
      snprintf(buf, sizeof(buf), "%s%c%s", path, DIRSEP, passwords_file);
      fp = fopen(buf, "r");
    } else {
      p = strrchr(path, DIRSEP);
      if (p == NULL) p = path;
      snprintf(buf, sizeof(buf), "%.*s%c%s", (int) (p - path), path, DIRSEP,
               passwords_file);
      fp = fopen(buf, "r");
    }

    if (fp != NULL) {
      authorized = mg_http_check_digest_auth(hm, domain, fp);
      fclose(fp);
    }
  }

  DBG(("%s %s %d %d", path, passwords_file ? passwords_file : "",
       is_global_pass_file, authorized));
  return authorized;
}
#else
static int mg_is_authorized(struct http_message *hm, const char *path,
                            int is_directory, const char *domain,
                            const char *passwords_file,
                            int is_global_pass_file) {
  (void) hm;
  (void) path;
  (void) is_directory;
  (void) domain;
  (void) passwords_file;
  (void) is_global_pass_file;
  return 1;
}
#endif

#ifndef MG_DISABLE_DIRECTORY_LISTING
static size_t mg_url_encode(const char *src, size_t s_len, char *dst,
                            size_t dst_len) {
  static const char *dont_escape = "._-$,;~()/";
  static const char *hex = "0123456789abcdef";
  size_t i = 0, j = 0;

  for (i = j = 0; dst_len > 0 && i < s_len && j + 2 < dst_len - 1; i++, j++) {
    if (isalnum(*(const unsigned char *) (src + i)) ||
        strchr(dont_escape, *(const unsigned char *) (src + i)) != NULL) {
      dst[j] = src[i];
    } else if (j + 3 < dst_len) {
      dst[j] = '%';
      dst[j + 1] = hex[(*(const unsigned char *) (src + i)) >> 4];
      dst[j + 2] = hex[(*(const unsigned char *) (src + i)) & 0xf];
      j += 2;
    }
  }

  dst[j] = '\0';
  return j;
}

static void mg_escape(const char *src, char *dst, size_t dst_len) {
  size_t n = 0;
  while (*src != '\0' && n + 5 < dst_len) {
    unsigned char ch = *(unsigned char *) src++;
    if (ch == '<') {
      n += snprintf(dst + n, dst_len - n, "%s", "&lt;");
    } else {
      dst[n++] = ch;
    }
  }
  dst[n] = '\0';
}

static void mg_print_dir_entry(struct mg_connection *nc, const char *file_name,
                               cs_stat_t *stp) {
  char size[64], mod[64], href[MAX_PATH_SIZE * 3], path[MAX_PATH_SIZE];
  int64_t fsize = stp->st_size;
  int is_dir = S_ISDIR(stp->st_mode);
  const char *slash = is_dir ? "/" : "";

  if (is_dir) {
    snprintf(size, sizeof(size), "%s", "[DIRECTORY]");
  } else {
    /*
     * We use (double) cast below because MSVC 6 compiler cannot
     * convert unsigned __int64 to double.
     */
    if (fsize < 1024) {
      snprintf(size, sizeof(size), "%d", (int) fsize);
    } else if (fsize < 0x100000) {
      snprintf(size, sizeof(size), "%.1fk", (double) fsize / 1024.0);
    } else if (fsize < 0x40000000) {
      snprintf(size, sizeof(size), "%.1fM", (double) fsize / 1048576);
    } else {
      snprintf(size, sizeof(size), "%.1fG", (double) fsize / 1073741824);
    }
  }
  strftime(mod, sizeof(mod), "%d-%b-%Y %H:%M", localtime(&stp->st_mtime));
  mg_escape(file_name, path, sizeof(path));
  mg_url_encode(file_name, strlen(file_name), href, sizeof(href));
  mg_printf_http_chunk(nc,
                       "<tr><td><a href=\"%s%s\">%s%s</a></td>"
                       "<td>%s</td><td name=%" INT64_FMT ">%s</td></tr>\n",
                       href, slash, path, slash, mod, is_dir ? -1 : fsize,
                       size);
}

static void mg_scan_directory(struct mg_connection *nc, const char *dir,
                              const struct mg_serve_http_opts *opts,
                              void (*func)(struct mg_connection *, const char *,
                                           cs_stat_t *)) {
  char path[MAX_PATH_SIZE];
  cs_stat_t st;
  struct dirent *dp;
  DIR *dirp;

  DBG(("%p [%s]", nc, dir));
  if ((dirp = (opendir(dir))) != NULL) {
    while ((dp = readdir(dirp)) != NULL) {
      /* Do not show current dir and hidden files */
      if (mg_is_file_hidden((const char *) dp->d_name, opts, 1)) {
        continue;
      }
      snprintf(path, sizeof(path), "%s/%s", dir, dp->d_name);
      if (mg_stat(path, &st) == 0) {
        func(nc, (const char *) dp->d_name, &st);
      }
    }
    closedir(dirp);
  } else {
    DBG(("%p opendir(%s) -> %d", nc, dir, errno));
  }
}

static void mg_send_directory_listing(struct mg_connection *nc, const char *dir,
                                      struct http_message *hm,
                                      struct mg_serve_http_opts *opts) {
  static const char *sort_js_code =
      "<script>function srt(tb, sc, so, d) {"
      "var tr = Array.prototype.slice.call(tb.rows, 0),"
      "tr = tr.sort(function (a, b) { var c1 = a.cells[sc], c2 = b.cells[sc],"
      "n1 = c1.getAttribute('name'), n2 = c2.getAttribute('name'), "
      "t1 = a.cells[2].getAttribute('name'), "
      "t2 = b.cells[2].getAttribute('name'); "
      "return so * (t1 < 0 && t2 >= 0 ? -1 : t2 < 0 && t1 >= 0 ? 1 : "
      "n1 ? parseInt(n2) - parseInt(n1) : "
      "c1.textContent.trim().localeCompare(c2.textContent.trim())); });";
  static const char *sort_js_code2 =
      "for (var i = 0; i < tr.length; i++) tb.appendChild(tr[i]); "
      "if (!d) window.location.hash = ('sc=' + sc + '&so=' + so); "
      "};"
      "window.onload = function() {"
      "var tb = document.getElementById('tb');"
      "var m = /sc=([012]).so=(1|-1)/.exec(window.location.hash) || [0, 2, 1];"
      "var sc = m[1], so = m[2]; document.onclick = function(ev) { "
      "var c = ev.target.rel; if (c) {if (c == sc) so *= -1; srt(tb, c, so); "
      "sc = c; ev.preventDefault();}};"
      "srt(tb, sc, so, true);"
      "}"
      "</script>";

  mg_send_response_line(nc, 200, opts->extra_headers);
  mg_printf(nc, "%s: %s\r\n%s: %s\r\n\r\n", "Transfer-Encoding", "chunked",
            "Content-Type", "text/html; charset=utf-8");

  mg_printf_http_chunk(
      nc,
      "<html><head><title>Index of %.*s</title>%s%s"
      "<style>th,td {text-align: left; padding-right: 1em; "
      "font-family: monospace; }</style></head>\n"
      "<body><h1>Index of %.*s</h1>\n<table cellpadding=0><thead>"
      "<tr><th><a href=# rel=0>Name</a></th><th>"
      "<a href=# rel=1>Modified</a</th>"
      "<th><a href=# rel=2>Size</a></th></tr>"
      "<tr><td colspan=3><hr></td></tr>\n"
      "</thead>\n"
      "<tbody id=tb>",
      (int) hm->uri.len, hm->uri.p, sort_js_code, sort_js_code2,
      (int) hm->uri.len, hm->uri.p);
  mg_scan_directory(nc, dir, opts, mg_print_dir_entry);
  mg_printf_http_chunk(nc,
                       "</tbody><tr><td colspan=3><hr></td></tr>\n"
                       "</table>\n"
                       "<address>%s</address>\n"
                       "</body></html>",
                       mg_version_header);
  mg_send_http_chunk(nc, "", 0);
  /* TODO(rojer): Remove when cesanta/dev/issues/197 is fixed. */
  nc->flags |= MG_F_SEND_AND_CLOSE;
}
#endif /* MG_DISABLE_DIRECTORY_LISTING */

#ifndef MG_DISABLE_DAV
static void mg_print_props(struct mg_connection *nc, const char *name,
                           cs_stat_t *stp) {
  char mtime[64], buf[MAX_PATH_SIZE * 3];
  time_t t = stp->st_mtime; /* store in local variable for NDK compile */
  mg_gmt_time_string(mtime, sizeof(mtime), &t);
  mg_url_encode(name, strlen(name), buf, sizeof(buf));
  mg_printf(nc,
            "<d:response>"
            "<d:href>%s</d:href>"
            "<d:propstat>"
            "<d:prop>"
            "<d:resourcetype>%s</d:resourcetype>"
            "<d:getcontentlength>%" INT64_FMT
            "</d:getcontentlength>"
            "<d:getlastmodified>%s</d:getlastmodified>"
            "</d:prop>"
            "<d:status>HTTP/1.1 200 OK</d:status>"
            "</d:propstat>"
            "</d:response>\n",
            buf, S_ISDIR(stp->st_mode) ? "<d:collection/>" : "",
            (int64_t) stp->st_size, mtime);
}

static void mg_handle_propfind(struct mg_connection *nc, const char *path,
                               cs_stat_t *stp, struct http_message *hm,
                               struct mg_serve_http_opts *opts) {
  static const char header[] =
      "HTTP/1.1 207 Multi-Status\r\n"
      "Connection: close\r\n"
      "Content-Type: text/xml; charset=utf-8\r\n\r\n"
      "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
      "<d:multistatus xmlns:d='DAV:'>\n";
  static const char footer[] = "</d:multistatus>\n";
  const struct mg_str *depth = mg_get_http_header(hm, "Depth");

  /* Print properties for the requested resource itself */
  if (S_ISDIR(stp->st_mode) &&
      strcmp(opts->enable_directory_listing, "yes") != 0) {
    mg_printf(nc, "%s", "HTTP/1.1 403 Directory Listing Denied\r\n\r\n");
  } else {
    char uri[MAX_PATH_SIZE];
    mg_send(nc, header, sizeof(header) - 1);
    snprintf(uri, sizeof(uri), "%.*s", (int) hm->uri.len, hm->uri.p);
    mg_print_props(nc, uri, stp);
    if (S_ISDIR(stp->st_mode) && (depth == NULL || mg_vcmp(depth, "0") != 0)) {
      mg_scan_directory(nc, path, opts, mg_print_props);
    }
    mg_send(nc, footer, sizeof(footer) - 1);
    nc->flags |= MG_F_SEND_AND_CLOSE;
  }
}

#ifdef MG_ENABLE_FAKE_DAVLOCK
/*
 * Windows explorer (probably there are another WebDav clients like it)
 * requires LOCK support in webdav. W/out this, it still works, but fails
 * to save file: shows error message and offers "Save As".
 * "Save as" works, but this message is very annoying.
 * This is fake lock, which doesn't lock something, just returns LOCK token,
 * UNLOCK always answers "OK".
 * With this fake LOCK Windows Explorer looks happy and saves file.
 * NOTE: that is not DAV LOCK imlementation, it is just a way to shut up
 * Windows native DAV client. This is why FAKE LOCK is not enabed by default
 */
static void mg_handle_lock(struct mg_connection *nc, const char *path) {
  static const char *reply =
      "HTTP/1.1 207 Multi-Status\r\n"
      "Connection: close\r\n"
      "Content-Type: text/xml; charset=utf-8\r\n\r\n"
      "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
      "<d:multistatus xmlns:d='DAV:'>\n"
      "<D:lockdiscovery>\n"
      "<D:activelock>\n"
      "<D:locktoken>\n"
      "<D:href>\n"
      "opaquelocktoken:%s%u"
      "</D:href>"
      "</D:locktoken>"
      "</D:activelock>\n"
      "</D:lockdiscovery>"
      "</d:multistatus>\n";
  mg_printf(nc, reply, path, (unsigned int) time(NULL));
  nc->flags |= MG_F_SEND_AND_CLOSE;
}
#endif

static void mg_handle_mkcol(struct mg_connection *nc, const char *path,
                            struct http_message *hm) {
  int status_code = 500;
  if (hm->body.len != (size_t) ~0 && hm->body.len > 0) {
    status_code = 415;
  } else if (!mg_mkdir(path, 0755)) {
    status_code = 201;
  } else if (errno == EEXIST) {
    status_code = 405;
  } else if (errno == EACCES) {
    status_code = 403;
  } else if (errno == ENOENT) {
    status_code = 409;
  } else {
    status_code = 500;
  }
  mg_http_send_error(nc, status_code, NULL);
}

static int mg_remove_directory(const struct mg_serve_http_opts *opts,
                               const char *dir) {
  char path[MAX_PATH_SIZE];
  struct dirent *dp;
  cs_stat_t st;
  DIR *dirp;

  if ((dirp = opendir(dir)) == NULL) return 0;

  while ((dp = readdir(dirp)) != NULL) {
    if (mg_is_file_hidden((const char *) dp->d_name, opts, 1)) {
      continue;
    }
    snprintf(path, sizeof(path), "%s%c%s", dir, '/', dp->d_name);
    mg_stat(path, &st);
    if (S_ISDIR(st.st_mode)) {
      mg_remove_directory(opts, path);
    } else {
      remove(path);
    }
  }
  closedir(dirp);
  rmdir(dir);

  return 1;
}

static void mg_handle_move(struct mg_connection *c,
                           const struct mg_serve_http_opts *opts,
                           const char *path, struct http_message *hm) {
  const struct mg_str *dest = mg_get_http_header(hm, "Destination");
  if (dest == NULL) {
    mg_http_send_error(c, 411, NULL);
  } else {
    const char *p = (char *) memchr(dest->p, '/', dest->len);
    if (p != NULL && p[1] == '/' &&
        (p = (char *) memchr(p + 2, '/', dest->p + dest->len - p)) != NULL) {
      char buf[MAX_PATH_SIZE];
      snprintf(buf, sizeof(buf), "%s%.*s", opts->dav_document_root,
               (int) (dest->p + dest->len - p), p);
      if (rename(path, buf) == 0) {
        mg_http_send_error(c, 200, NULL);
      } else {
        mg_http_send_error(c, 418, NULL);
      }
    } else {
      mg_http_send_error(c, 500, NULL);
    }
  }
}

static void mg_handle_delete(struct mg_connection *nc,
                             const struct mg_serve_http_opts *opts,
                             const char *path) {
  cs_stat_t st;
  if (mg_stat(path, &st) != 0) {
    mg_http_send_error(nc, 404, NULL);
  } else if (S_ISDIR(st.st_mode)) {
    mg_remove_directory(opts, path);
    mg_http_send_error(nc, 204, NULL);
  } else if (remove(path) == 0) {
    mg_http_send_error(nc, 204, NULL);
  } else {
    mg_http_send_error(nc, 423, NULL);
  }
}

/* Return -1 on error, 1 on success. */
static int mg_create_itermediate_directories(const char *path) {
  const char *s;

  /* Create intermediate directories if they do not exist */
  for (s = path + 1; *s != '\0'; s++) {
    if (*s == '/') {
      char buf[MAX_PATH_SIZE];
      cs_stat_t st;
      snprintf(buf, sizeof(buf), "%.*s", (int) (s - path), path);
      buf[sizeof(buf) - 1] = '\0';
      if (mg_stat(buf, &st) != 0 && mg_mkdir(buf, 0755) != 0) {
        return -1;
      }
    }
  }

  return 1;
}

static void mg_handle_put(struct mg_connection *nc, const char *path,
                          struct http_message *hm) {
  struct mg_http_proto_data *pd = mg_http_get_proto_data(nc);
  cs_stat_t st;
  const struct mg_str *cl_hdr = mg_get_http_header(hm, "Content-Length");
  int rc, status_code = mg_stat(path, &st) == 0 ? 200 : 201;

  mg_http_free_proto_data_file(&pd->file);
  if ((rc = mg_create_itermediate_directories(path)) == 0) {
    mg_printf(nc, "HTTP/1.1 %d OK\r\nContent-Length: 0\r\n\r\n", status_code);
  } else if (rc == -1) {
    mg_http_send_error(nc, 500, NULL);
  } else if (cl_hdr == NULL) {
    mg_http_send_error(nc, 411, NULL);
  } else if ((pd->file.fp = fopen(path, "w+b")) == NULL) {
    mg_http_send_error(nc, 500, NULL);
  } else {
    const struct mg_str *range_hdr = mg_get_http_header(hm, "Content-Range");
    int64_t r1 = 0, r2 = 0;
    pd->file.type = DATA_PUT;
    mg_set_close_on_exec(fileno(pd->file.fp));
    pd->file.cl = to64(cl_hdr->p);
    if (range_hdr != NULL &&
        mg_http_parse_range_header(range_hdr, &r1, &r2) > 0) {
      status_code = 206;
      fseeko(pd->file.fp, r1, SEEK_SET);
      pd->file.cl = r2 > r1 ? r2 - r1 + 1 : pd->file.cl - r1;
    }
    mg_printf(nc, "HTTP/1.1 %d OK\r\nContent-Length: 0\r\n\r\n", status_code);
    /* Remove HTTP request from the mbuf, leave only payload */
    mbuf_remove(&nc->recv_mbuf, hm->message.len - hm->body.len);
    mg_http_transfer_file_data(nc);
  }
}
#endif /* MG_DISABLE_DAV */

static int mg_is_dav_request(const struct mg_str *s) {
  static const char *methods[] = {"PUT", "DELETE", "MKCOL", "PROPFIND", "MOVE"
#ifdef MG_ENABLE_FAKE_DAVLOCK
                                  ,
                                  "LOCK", "UNLOCK"
#endif
  };
  size_t i;

  for (i = 0; i < ARRAY_SIZE(methods); i++) {
    if (mg_vcmp(s, methods[i]) == 0) {
      return 1;
    }
  }

  return 0;
}

/*
 * Given a directory path, find one of the files specified in the
 * comma-separated list of index files `list`.
 * First found index file wins. If an index file is found, then gets
 * appended to the `path`, stat-ed, and result of `stat()` passed to `stp`.
 * If index file is not found, then `path` and `stp` remain unchanged.
 */
MG_INTERNAL void mg_find_index_file(const char *path, const char *list,
                                    char **index_file, cs_stat_t *stp) {
  struct mg_str vec;
  size_t path_len = strlen(path);
  int found = 0;
  *index_file = NULL;

  /* Traverse index files list. For each entry, append it to the given */
  /* path and see if the file exists. If it exists, break the loop */
  while ((list = mg_next_comma_list_entry(list, &vec, NULL)) != NULL) {
    cs_stat_t st;
    size_t len = path_len + 1 + vec.len + 1;
    *index_file = (char *) MG_REALLOC(*index_file, len);
    if (*index_file == NULL) break;
    snprintf(*index_file, len, "%s%c%.*s", path, DIRSEP, (int) vec.len, vec.p);

    /* Does it exist? Is it a file? */
    if (mg_stat(*index_file, &st) == 0 && S_ISREG(st.st_mode)) {
      /* Yes it does, break the loop */
      *stp = st;
      found = 1;
      break;
    }
  }
  if (!found) {
    MG_FREE(*index_file);
    *index_file = NULL;
  }
  DBG(("[%s] [%s]", path, (*index_file ? *index_file : "")));
}

static int mg_http_send_port_based_redirect(
    struct mg_connection *c, struct http_message *hm,
    const struct mg_serve_http_opts *opts) {
  const char *rewrites = opts->url_rewrites;
  struct mg_str a, b;
  char local_port[20] = {'%'};

  mg_conn_addr_to_str(c, local_port + 1, sizeof(local_port) - 1,
                      MG_SOCK_STRINGIFY_PORT);

  while ((rewrites = mg_next_comma_list_entry(rewrites, &a, &b)) != NULL) {
    if (mg_vcmp(&a, local_port) == 0) {
      mg_send_response_line(c, 301, NULL);
      mg_printf(c, "Content-Length: 0\r\nLocation: %.*s%.*s\r\n\r\n",
                (int) b.len, b.p, (int) (hm->proto.p - hm->uri.p - 1),
                hm->uri.p);
      return 1;
    }
  }

  return 0;
}

MG_INTERNAL int mg_uri_to_local_path(struct http_message *hm,
                                     const struct mg_serve_http_opts *opts,
                                     char **local_path,
                                     struct mg_str *remainder) {
  int ok = 1;
  const char *cp = hm->uri.p, *cp_end = hm->uri.p + hm->uri.len;
  struct mg_str root = {NULL, 0};
  const char *file_uri_start = cp;
  *local_path = NULL;
  remainder->p = NULL;
  remainder->len = 0;

  { /* 1. Determine which root to use. */
    const char *rewrites = opts->url_rewrites;
    struct mg_str *hh = mg_get_http_header(hm, "Host");
    struct mg_str a, b;
    /* Check rewrites first. */
    while ((rewrites = mg_next_comma_list_entry(rewrites, &a, &b)) != NULL) {
      if (a.len > 1 && a.p[0] == '@') {
        /* Host rewrite. */
        if (hh != NULL && hh->len == a.len - 1 &&
            mg_ncasecmp(a.p + 1, hh->p, a.len - 1) == 0) {
          root = b;
          break;
        }
      } else {
        /* Regular rewrite, URI=directory */
        int match_len = mg_match_prefix_n(a, hm->uri);
        if (match_len > 0) {
          file_uri_start = hm->uri.p + match_len;
          if (*file_uri_start == '/' || file_uri_start == cp_end) {
            /* Match ended at component boundary, ok. */
          } else if (*(file_uri_start - 1) == '/') {
            /* Pattern ends with '/', backtrack. */
            file_uri_start--;
          } else {
            /* No match: must fall on the component boundary. */
            continue;
          }
          root = b;
          break;
        }
      }
    }
    /* If no rewrite rules matched, use DAV or regular document root. */
    if (root.p == NULL) {
#ifndef MG_DISABLE_DAV
      if (opts->dav_document_root != NULL && mg_is_dav_request(&hm->method)) {
        root.p = opts->dav_document_root;
        root.len = strlen(opts->dav_document_root);
      } else
#endif
      {
        root.p = opts->document_root;
        root.len = strlen(opts->document_root);
      }
    }
    assert(root.p != NULL && root.len > 0);
  }

  { /* 2. Find where in the canonical URI path the local path ends. */
    const char *u = file_uri_start + 1;
    char *lp = (char *) MG_MALLOC(root.len + hm->uri.len + 1);
    char *lp_end = lp + root.len + hm->uri.len + 1;
    char *p = lp, *ps;
    int exists = 1;
    if (lp == NULL) {
      ok = 0;
      goto out;
    }
    memcpy(p, root.p, root.len);
    p += root.len;
    if (*(p - 1) == DIRSEP) p--;
    *p = '\0';
    ps = p;

    /* Chop off URI path components one by one and build local path. */
    while (u <= cp_end) {
      const char *next = u;
      struct mg_str component;
      if (exists) {
        cs_stat_t st;
        exists = (mg_stat(lp, &st) == 0);
        if (exists && S_ISREG(st.st_mode)) {
          /* We found the terminal, the rest of the URI (if any) is path_info.
           */
          if (*(u - 1) == '/') u--;
          break;
        }
      }
      if (u >= cp_end) break;
      parse_uri_component((const char **) &next, cp_end, '/', &component);
      if (component.len > 0) {
        int len;
        memmove(p + 1, component.p, component.len);
        len = mg_url_decode(p + 1, component.len, p + 1, lp_end - p - 1, 0);
        if (len <= 0) {
          ok = 0;
          break;
        }
        component.p = p + 1;
        component.len = len;
        if (mg_vcmp(&component, ".") == 0) {
          /* Yum. */
        } else if (mg_vcmp(&component, "..") == 0) {
          while (p > ps && *p != DIRSEP) p--;
          *p = '\0';
        } else {
          size_t i;
#ifdef _WIN32
          /* On Windows, make sure it's valid Unicode (no funny stuff). */
          wchar_t buf[MG_MAX_PATH * 2];
          if (to_wchar(component.p, buf, MG_MAX_PATH) == 0) {
            DBG(("[%.*s] smells funny", (int) component.len, component.p));
            ok = 0;
            break;
          }
#endif
          *p++ = DIRSEP;
          /* No NULs and DIRSEPs in the component (percent-encoded). */
          for (i = 0; i < component.len; i++, p++) {
            if (*p == '\0' || *p == DIRSEP
#ifdef _WIN32
                /* On Windows, "/" is also accepted, so check for that too. */
                ||
                *p == '/'
#endif
                ) {
              ok = 0;
              break;
            }
          }
        }
      }
      u = next;
    }
    if (ok) {
      *local_path = lp;
      if (u > cp_end) u = cp_end;
      remainder->p = u;
      remainder->len = cp_end - u;
    } else {
      MG_FREE(lp);
    }
  }

out:
  DBG(("'%.*s' -> '%s' + '%.*s'", (int) hm->uri.len, hm->uri.p,
       *local_path ? *local_path : "", (int) remainder->len, remainder->p));
  return ok;
}

#ifndef MG_DISABLE_CGI
#ifdef _WIN32
struct mg_threadparam {
  sock_t s;
  HANDLE hPipe;
};

static int mg_wait_until_ready(sock_t sock, int for_read) {
  fd_set set;
  FD_ZERO(&set);
  FD_SET(sock, &set);
  return select(sock + 1, for_read ? &set : 0, for_read ? 0 : &set, 0, 0) == 1;
}

static void *mg_push_to_stdin(void *arg) {
  struct mg_threadparam *tp = (struct mg_threadparam *) arg;
  int n, sent, stop = 0;
  DWORD k;
  char buf[BUFSIZ];

  while (!stop && mg_wait_until_ready(tp->s, 1) &&
         (n = recv(tp->s, buf, sizeof(buf), 0)) > 0) {
    if (n == -1 && GetLastError() == WSAEWOULDBLOCK) continue;
    for (sent = 0; !stop && sent < n; sent += k) {
      if (!WriteFile(tp->hPipe, buf + sent, n - sent, &k, 0)) stop = 1;
    }
  }
  DBG(("%s", "FORWARED EVERYTHING TO CGI"));
  CloseHandle(tp->hPipe);
  MG_FREE(tp);
  _endthread();
  return NULL;
}

static void *mg_pull_from_stdout(void *arg) {
  struct mg_threadparam *tp = (struct mg_threadparam *) arg;
  int k = 0, stop = 0;
  DWORD n, sent;
  char buf[BUFSIZ];

  while (!stop && ReadFile(tp->hPipe, buf, sizeof(buf), &n, NULL)) {
    for (sent = 0; !stop && sent < n; sent += k) {
      if (mg_wait_until_ready(tp->s, 0) &&
          (k = send(tp->s, buf + sent, n - sent, 0)) <= 0)
        stop = 1;
    }
  }
  DBG(("%s", "EOF FROM CGI"));
  CloseHandle(tp->hPipe);
  shutdown(tp->s, 2);  // Without this, IO thread may get truncated data
  closesocket(tp->s);
  MG_FREE(tp);
  _endthread();
  return NULL;
}

static void mg_spawn_stdio_thread(sock_t sock, HANDLE hPipe,
                                  void *(*func)(void *)) {
  struct mg_threadparam *tp = (struct mg_threadparam *) MG_MALLOC(sizeof(*tp));
  if (tp != NULL) {
    tp->s = sock;
    tp->hPipe = hPipe;
    mg_start_thread(func, tp);
  }
}

static void mg_abs_path(const char *utf8_path, char *abs_path, size_t len) {
  wchar_t buf[MAX_PATH_SIZE], buf2[MAX_PATH_SIZE];
  to_wchar(utf8_path, buf, ARRAY_SIZE(buf));
  GetFullPathNameW(buf, ARRAY_SIZE(buf2), buf2, NULL);
  WideCharToMultiByte(CP_UTF8, 0, buf2, wcslen(buf2) + 1, abs_path, len, 0, 0);
}

static int mg_start_process(const char *interp, const char *cmd,
                            const char *env, const char *envp[],
                            const char *dir, sock_t sock) {
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  HANDLE a[2], b[2], me = GetCurrentProcess();
  wchar_t wcmd[MAX_PATH_SIZE], full_dir[MAX_PATH_SIZE];
  char buf[MAX_PATH_SIZE], buf2[MAX_PATH_SIZE], buf5[MAX_PATH_SIZE],
      buf4[MAX_PATH_SIZE], cmdline[MAX_PATH_SIZE];
  DWORD flags = DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS;
  FILE *fp;

  memset(&si, 0, sizeof(si));
  memset(&pi, 0, sizeof(pi));

  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

  CreatePipe(&a[0], &a[1], NULL, 0);
  CreatePipe(&b[0], &b[1], NULL, 0);
  DuplicateHandle(me, a[0], me, &si.hStdInput, 0, TRUE, flags);
  DuplicateHandle(me, b[1], me, &si.hStdOutput, 0, TRUE, flags);

  if (interp == NULL && (fp = fopen(cmd, "r")) != NULL) {
    buf[0] = buf[1] = '\0';
    fgets(buf, sizeof(buf), fp);
    buf[sizeof(buf) - 1] = '\0';
    if (buf[0] == '#' && buf[1] == '!') {
      interp = buf + 2;
      /* Trim leading spaces: https://github.com/cesanta/mongoose/issues/489 */
      while (*interp != '\0' && isspace(*(unsigned char *) interp)) {
        interp++;
      }
    }
    fclose(fp);
  }

  snprintf(buf, sizeof(buf), "%s/%s", dir, cmd);
  mg_abs_path(buf, buf2, ARRAY_SIZE(buf2));

  mg_abs_path(dir, buf5, ARRAY_SIZE(buf5));
  to_wchar(dir, full_dir, ARRAY_SIZE(full_dir));

  if (interp != NULL) {
    mg_abs_path(interp, buf4, ARRAY_SIZE(buf4));
    snprintf(cmdline, sizeof(cmdline), "%s \"%s\"", buf4, buf2);
  } else {
    snprintf(cmdline, sizeof(cmdline), "\"%s\"", buf2);
  }
  to_wchar(cmdline, wcmd, ARRAY_SIZE(wcmd));

  if (CreateProcessW(NULL, wcmd, NULL, NULL, TRUE, CREATE_NEW_PROCESS_GROUP,
                     (void *) env, full_dir, &si, &pi) != 0) {
    mg_spawn_stdio_thread(sock, a[1], mg_push_to_stdin);
    mg_spawn_stdio_thread(sock, b[0], mg_pull_from_stdout);

    CloseHandle(si.hStdOutput);
    CloseHandle(si.hStdInput);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
  } else {
    CloseHandle(a[1]);
    CloseHandle(b[0]);
    closesocket(sock);
  }
  DBG(("CGI command: [%ls] -> %p", wcmd, pi.hProcess));

  /* Not closing a[0] and b[1] because we've used DUPLICATE_CLOSE_SOURCE */
  (void) envp;
  return (pi.hProcess != NULL);
}
#else
static int mg_start_process(const char *interp, const char *cmd,
                            const char *env, const char *envp[],
                            const char *dir, sock_t sock) {
  char buf[500];
  pid_t pid = fork();
  (void) env;

  if (pid == 0) {
    /*
     * In Linux `chdir` declared with `warn_unused_result` attribute
     * To shutup compiler we have yo use result in some way
     */
    int tmp = chdir(dir);
    (void) tmp;
    (void) dup2(sock, 0);
    (void) dup2(sock, 1);
    closesocket(sock);

    /*
     * After exec, all signal handlers are restored to their default values,
     * with one exception of SIGCHLD. According to POSIX.1-2001 and Linux's
     * implementation, SIGCHLD's handler will leave unchanged after exec
     * if it was set to be ignored. Restore it to default action.
     */
    signal(SIGCHLD, SIG_DFL);

    if (interp == NULL) {
      execle(cmd, cmd, (char *) 0, envp); /* (char *) 0 to squash warning */
    } else {
      execle(interp, interp, cmd, (char *) 0, envp);
    }
    snprintf(buf, sizeof(buf),
             "Status: 500\r\n\r\n"
             "500 Server Error: %s%s%s: %s",
             interp == NULL ? "" : interp, interp == NULL ? "" : " ", cmd,
             strerror(errno));
    send(1, buf, strlen(buf), 0);
    exit(EXIT_FAILURE); /* exec call failed */
  }

  return (pid != 0);
}
#endif /* _WIN32 */

/*
 * Append VARIABLE=VALUE\0 string to the buffer, and add a respective
 * pointer into the vars array.
 */
static char *mg_addenv(struct mg_cgi_env_block *block, const char *fmt, ...) {
  int n, space;
  char *added = block->buf + block->len;
  va_list ap;

  /* Calculate how much space is left in the buffer */
  space = sizeof(block->buf) - (block->len + 2);
  if (space > 0) {
    /* Copy VARIABLE=VALUE\0 string into the free space */
    va_start(ap, fmt);
    n = vsnprintf(added, (size_t) space, fmt, ap);
    va_end(ap);

    /* Make sure we do not overflow buffer and the envp array */
    if (n > 0 && n + 1 < space &&
        block->nvars < (int) ARRAY_SIZE(block->vars) - 2) {
      /* Append a pointer to the added string into the envp array */
      block->vars[block->nvars++] = added;
      /* Bump up used length counter. Include \0 terminator */
      block->len += n + 1;
    }
  }

  return added;
}

static void mg_addenv2(struct mg_cgi_env_block *blk, const char *name) {
  const char *s;
  if ((s = getenv(name)) != NULL) mg_addenv(blk, "%s=%s", name, s);
}

static void mg_prepare_cgi_environment(struct mg_connection *nc,
                                       const char *prog,
                                       const struct mg_str *path_info,
                                       const struct http_message *hm,
                                       const struct mg_serve_http_opts *opts,
                                       struct mg_cgi_env_block *blk) {
  const char *s;
  struct mg_str *h;
  char *p;
  size_t i;
  char buf[100];

  blk->len = blk->nvars = 0;
  blk->nc = nc;

  if ((s = getenv("SERVER_NAME")) != NULL) {
    mg_addenv(blk, "SERVER_NAME=%s", s);
  } else {
    mg_sock_to_str(nc->sock, buf, sizeof(buf), 3);
    mg_addenv(blk, "SERVER_NAME=%s", buf);
  }
  mg_addenv(blk, "SERVER_ROOT=%s", opts->document_root);
  mg_addenv(blk, "DOCUMENT_ROOT=%s", opts->document_root);
  mg_addenv(blk, "SERVER_SOFTWARE=%s/%s", "Mongoose", MG_VERSION);

  /* Prepare the environment block */
  mg_addenv(blk, "%s", "GATEWAY_INTERFACE=CGI/1.1");
  mg_addenv(blk, "%s", "SERVER_PROTOCOL=HTTP/1.1");
  mg_addenv(blk, "%s", "REDIRECT_STATUS=200"); /* For PHP */

  mg_addenv(blk, "REQUEST_METHOD=%.*s", (int) hm->method.len, hm->method.p);

  mg_addenv(blk, "REQUEST_URI=%.*s%s%.*s", (int) hm->uri.len, hm->uri.p,
            hm->query_string.len == 0 ? "" : "?", (int) hm->query_string.len,
            hm->query_string.p);

  mg_conn_addr_to_str(nc, buf, sizeof(buf),
                      MG_SOCK_STRINGIFY_REMOTE | MG_SOCK_STRINGIFY_IP);
  mg_addenv(blk, "REMOTE_ADDR=%s", buf);
  mg_conn_addr_to_str(nc, buf, sizeof(buf), MG_SOCK_STRINGIFY_PORT);
  mg_addenv(blk, "SERVER_PORT=%s", buf);

  s = hm->uri.p + hm->uri.len - path_info->len - 1;
  if (*s == '/') {
    const char *base_name = strrchr(prog, DIRSEP);
    mg_addenv(blk, "SCRIPT_NAME=%.*s/%s", (int) (s - hm->uri.p), hm->uri.p,
              (base_name != NULL ? base_name + 1 : prog));
  } else {
    mg_addenv(blk, "SCRIPT_NAME=%.*s", (int) (s - hm->uri.p + 1), hm->uri.p);
  }
  mg_addenv(blk, "SCRIPT_FILENAME=%s", prog);

  if (path_info != NULL && path_info->len > 0) {
    mg_addenv(blk, "PATH_INFO=%.*s", (int) path_info->len, path_info->p);
    /* Not really translated... */
    mg_addenv(blk, "PATH_TRANSLATED=%.*s", (int) path_info->len, path_info->p);
  }

#ifdef MG_ENABLE_SSL
  mg_addenv(blk, "HTTPS=%s", nc->ssl != NULL ? "on" : "off");
#else
  mg_addenv(blk, "HTTPS=off");
#endif

  if ((h = mg_get_http_header((struct http_message *) hm, "Content-Type")) !=
      NULL) {
    mg_addenv(blk, "CONTENT_TYPE=%.*s", (int) h->len, h->p);
  }

  if (hm->query_string.len > 0) {
    mg_addenv(blk, "QUERY_STRING=%.*s", (int) hm->query_string.len,
              hm->query_string.p);
  }

  if ((h = mg_get_http_header((struct http_message *) hm, "Content-Length")) !=
      NULL) {
    mg_addenv(blk, "CONTENT_LENGTH=%.*s", (int) h->len, h->p);
  }

  mg_addenv2(blk, "PATH");
  mg_addenv2(blk, "TMP");
  mg_addenv2(blk, "TEMP");
  mg_addenv2(blk, "TMPDIR");
  mg_addenv2(blk, "PERLLIB");
  mg_addenv2(blk, MG_ENV_EXPORT_TO_CGI);

#if defined(_WIN32)
  mg_addenv2(blk, "COMSPEC");
  mg_addenv2(blk, "SYSTEMROOT");
  mg_addenv2(blk, "SystemDrive");
  mg_addenv2(blk, "ProgramFiles");
  mg_addenv2(blk, "ProgramFiles(x86)");
  mg_addenv2(blk, "CommonProgramFiles(x86)");
#else
  mg_addenv2(blk, "LD_LIBRARY_PATH");
#endif /* _WIN32 */

  /* Add all headers as HTTP_* variables */
  for (i = 0; hm->header_names[i].len > 0; i++) {
    p = mg_addenv(blk, "HTTP_%.*s=%.*s", (int) hm->header_names[i].len,
                  hm->header_names[i].p, (int) hm->header_values[i].len,
                  hm->header_values[i].p);

    /* Convert variable name into uppercase, and change - to _ */
    for (; *p != '=' && *p != '\0'; p++) {
      if (*p == '-') *p = '_';
      *p = (char) toupper(*(unsigned char *) p);
    }
  }

  blk->vars[blk->nvars++] = NULL;
  blk->buf[blk->len++] = '\0';
}

static void mg_cgi_ev_handler(struct mg_connection *cgi_nc, int ev,
                              void *ev_data) {
  struct mg_connection *nc = (struct mg_connection *) cgi_nc->user_data;
  (void) ev_data;

  if (nc == NULL) return;

  switch (ev) {
    case MG_EV_RECV:
      /*
       * CGI script does not output reply line, like "HTTP/1.1 CODE XXXXX\n"
       * It outputs headers, then body. Headers might include "Status"
       * header, which changes CODE, and it might include "Location" header
       * which changes CODE to 302.
       *
       * Therefore we do not send the output from the CGI script to the user
       * until all CGI headers are received.
       *
       * Here we parse the output from the CGI script, and if all headers has
       * been received, send appropriate reply line, and forward all
       * received headers to the client.
       */
      if (nc->flags & MG_F_USER_1) {
        struct mbuf *io = &cgi_nc->recv_mbuf;
        int len = mg_http_get_request_len(io->buf, io->len);

        if (len == 0) break;
        if (len < 0 || io->len > MG_MAX_HTTP_REQUEST_SIZE) {
          cgi_nc->flags |= MG_F_CLOSE_IMMEDIATELY;
          mg_http_send_error(nc, 500, "Bad headers");
        } else {
          struct http_message hm;
          struct mg_str *h;
          mg_http_parse_headers(io->buf, io->buf + io->len, io->len, &hm);
          if (mg_get_http_header(&hm, "Location") != NULL) {
            mg_printf(nc, "%s", "HTTP/1.1 302 Moved\r\n");
          } else if ((h = mg_get_http_header(&hm, "Status")) != NULL) {
            mg_printf(nc, "HTTP/1.1 %.*s\r\n", (int) h->len, h->p);
          } else {
            mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\n");
          }
        }
        nc->flags &= ~MG_F_USER_1;
      }
      if (!(nc->flags & MG_F_USER_1)) {
        mg_forward(cgi_nc, nc);
      }
      break;
    case MG_EV_CLOSE:
      mg_http_free_proto_data_cgi(&mg_http_get_proto_data(cgi_nc)->cgi);
      nc->flags |= MG_F_SEND_AND_CLOSE;
      break;
  }
}

static void mg_handle_cgi(struct mg_connection *nc, const char *prog,
                          const struct mg_str *path_info,
                          const struct http_message *hm,
                          const struct mg_serve_http_opts *opts) {
  struct mg_cgi_env_block blk;
  char dir[MAX_PATH_SIZE];
  const char *p;
  sock_t fds[2];

  DBG(("%p [%s]", nc, prog));
  mg_prepare_cgi_environment(nc, prog, path_info, hm, opts, &blk);
  /*
   * CGI must be executed in its own directory. 'dir' must point to the
   * directory containing executable program, 'p' must point to the
   * executable program name relative to 'dir'.
   */
  if ((p = strrchr(prog, DIRSEP)) == NULL) {
    snprintf(dir, sizeof(dir), "%s", ".");
  } else {
    snprintf(dir, sizeof(dir), "%.*s", (int) (p - prog), prog);
    prog = p + 1;
  }

  /*
   * Try to create socketpair in a loop until success. mg_socketpair()
   * can be interrupted by a signal and fail.
   * TODO(lsm): use sigaction to restart interrupted syscall
   */
  do {
    mg_socketpair(fds, SOCK_STREAM);
  } while (fds[0] == INVALID_SOCKET);

  if (mg_start_process(opts->cgi_interpreter, prog, blk.buf, blk.vars, dir,
                       fds[1]) != 0) {
    size_t n = nc->recv_mbuf.len - (hm->message.len - hm->body.len);
    struct mg_connection *cgi_nc =
        mg_add_sock(nc->mgr, fds[0], mg_cgi_ev_handler);
    struct mg_http_proto_data *cgi_pd = mg_http_get_proto_data(cgi_nc);
    cgi_pd->cgi.cgi_nc = cgi_nc;
    cgi_pd->cgi.cgi_nc->user_data = nc;
    nc->flags |= MG_F_USER_1;
    /* Push POST data to the CGI */
    if (n > 0 && n < nc->recv_mbuf.len) {
      mg_send(cgi_pd->cgi.cgi_nc, hm->body.p, n);
    }
    mbuf_remove(&nc->recv_mbuf, nc->recv_mbuf.len);
  } else {
    closesocket(fds[0]);
    mg_http_send_error(nc, 500, "CGI failure");
  }

#ifndef _WIN32
  closesocket(fds[1]); /* On Windows, CGI stdio thread closes that socket */
#endif
}
#endif

static int mg_get_month_index(const char *s) {
  static const char *month_names[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  size_t i;

  for (i = 0; i < ARRAY_SIZE(month_names); i++)
    if (!strcmp(s, month_names[i])) return (int) i;

  return -1;
}

static int mg_num_leap_years(int year) {
  return year / 4 - year / 100 + year / 400;
}

/* Parse UTC date-time string, and return the corresponding time_t value. */
MG_INTERNAL time_t mg_parse_date_string(const char *datetime) {
  static const unsigned short days_before_month[] = {
      0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};
  char month_str[32];
  int second, minute, hour, day, month, year, leap_days, days;
  time_t result = (time_t) 0;

  if (((sscanf(datetime, "%d/%3s/%d %d:%d:%d", &day, month_str, &year, &hour,
               &minute, &second) == 6) ||
       (sscanf(datetime, "%d %3s %d %d:%d:%d", &day, month_str, &year, &hour,
               &minute, &second) == 6) ||
       (sscanf(datetime, "%*3s, %d %3s %d %d:%d:%d", &day, month_str, &year,
               &hour, &minute, &second) == 6) ||
       (sscanf(datetime, "%d-%3s-%d %d:%d:%d", &day, month_str, &year, &hour,
               &minute, &second) == 6)) &&
      year > 1970 && (month = mg_get_month_index(month_str)) != -1) {
    leap_days = mg_num_leap_years(year) - mg_num_leap_years(1970);
    year -= 1970;
    days = year * 365 + days_before_month[month] + (day - 1) + leap_days;
    result = days * 24 * 3600 + hour * 3600 + minute * 60 + second;
  }

  return result;
}

MG_INTERNAL int mg_is_not_modified(struct http_message *hm, cs_stat_t *st) {
  struct mg_str *hdr;
  if ((hdr = mg_get_http_header(hm, "If-None-Match")) != NULL) {
    char etag[64];
    mg_http_construct_etag(etag, sizeof(etag), st);
    return mg_vcasecmp(hdr, etag) == 0;
  } else if ((hdr = mg_get_http_header(hm, "If-Modified-Since")) != NULL) {
    return st->st_mtime <= mg_parse_date_string(hdr->p);
  } else {
    return 0;
  }
}

static void mg_http_send_digest_auth_request(struct mg_connection *c,
                                             const char *domain) {
  mg_printf(c,
            "HTTP/1.1 401 Unauthorized\r\n"
            "WWW-Authenticate: Digest qop=\"auth\", "
            "realm=\"%s\", nonce=\"%lu\"\r\n"
            "Content-Length: 0\r\n\r\n",
            domain, (unsigned long) time(NULL));
}

static void mg_http_send_options(struct mg_connection *nc) {
  mg_printf(nc, "%s",
            "HTTP/1.1 200 OK\r\nAllow: GET, POST, HEAD, CONNECT, OPTIONS"
#ifndef MG_DISABLE_DAV
            ", MKCOL, PUT, DELETE, PROPFIND, MOVE\r\nDAV: 1,2"
#endif
            "\r\n\r\n");
  nc->flags |= MG_F_SEND_AND_CLOSE;
}

static int mg_is_creation_request(const struct http_message *hm) {
  return mg_vcmp(&hm->method, "MKCOL") == 0 || mg_vcmp(&hm->method, "PUT") == 0;
}

MG_INTERNAL void mg_send_http_file(struct mg_connection *nc, char *path,
                                   const struct mg_str *path_info,
                                   struct http_message *hm,
                                   struct mg_serve_http_opts *opts) {
  int exists, is_directory, is_dav = mg_is_dav_request(&hm->method);
  int is_cgi;
  char *index_file = NULL;
  cs_stat_t st;

  exists = (mg_stat(path, &st) == 0);
  is_directory = exists && S_ISDIR(st.st_mode);

  if (is_directory)
    mg_find_index_file(path, opts->index_files, &index_file, &st);

  is_cgi =
      (mg_match_prefix(opts->cgi_file_pattern, strlen(opts->cgi_file_pattern),
                       index_file ? index_file : path) > 0);

  DBG(("%p %.*s [%s] exists=%d is_dir=%d is_dav=%d is_cgi=%d index=%s", nc,
       (int) hm->method.len, hm->method.p, path, exists, is_directory, is_dav,
       is_cgi, index_file ? index_file : ""));

  if (is_directory && hm->uri.p[hm->uri.len - 1] != '/' && !is_dav) {
    mg_printf(nc,
              "HTTP/1.1 301 Moved\r\nLocation: %.*s/\r\n"
              "Content-Length: 0\r\n\r\n",
              (int) hm->uri.len, hm->uri.p);
    MG_FREE(index_file);
    return;
  }

  /* If we have path_info, the only way to handle it is CGI. */
  if (path_info->len > 0 && !is_cgi) {
    mg_http_send_error(nc, 501, NULL);
    MG_FREE(index_file);
    return;
  }

  if (is_dav && opts->dav_document_root == NULL) {
    mg_http_send_error(nc, 501, NULL);
  } else if (!mg_is_authorized(hm, path, is_directory, opts->auth_domain,
                               opts->global_auth_file, 1) ||
             !mg_is_authorized(hm, path, is_directory, opts->auth_domain,
                               opts->per_directory_auth_file, 0)) {
    mg_http_send_digest_auth_request(nc, opts->auth_domain);
  } else if (is_cgi) {
#if !defined(MG_DISABLE_CGI)
    mg_handle_cgi(nc, index_file ? index_file : path, path_info, hm, opts);
#else
    mg_http_send_error(nc, 501, NULL);
#endif /* MG_DISABLE_CGI */
  } else if ((!exists ||
              mg_is_file_hidden(path, opts, 0 /* specials are ok */)) &&
             !mg_is_creation_request(hm)) {
    mg_http_send_error(nc, 404, NULL);
#ifndef MG_DISABLE_DAV
  } else if (!mg_vcmp(&hm->method, "PROPFIND")) {
    mg_handle_propfind(nc, path, &st, hm, opts);
#ifndef MG_DISABLE_DAV_AUTH
  } else if (is_dav &&
             (opts->dav_auth_file == NULL ||
              (strcmp(opts->dav_auth_file, "-") != 0 &&
               !mg_is_authorized(hm, path, is_directory, opts->auth_domain,
                                 opts->dav_auth_file, 1)))) {
    mg_http_send_digest_auth_request(nc, opts->auth_domain);
#endif
  } else if (!mg_vcmp(&hm->method, "MKCOL")) {
    mg_handle_mkcol(nc, path, hm);
  } else if (!mg_vcmp(&hm->method, "DELETE")) {
    mg_handle_delete(nc, opts, path);
  } else if (!mg_vcmp(&hm->method, "PUT")) {
    mg_handle_put(nc, path, hm);
  } else if (!mg_vcmp(&hm->method, "MOVE")) {
    mg_handle_move(nc, opts, path, hm);
#ifdef MG_ENABLE_FAKE_DAVLOCK
  } else if (!mg_vcmp(&hm->method, "LOCK")) {
    mg_handle_lock(nc, path);
#endif
#endif
  } else if (!mg_vcmp(&hm->method, "OPTIONS")) {
    mg_http_send_options(nc);
  } else if (is_directory && index_file == NULL) {
#ifndef MG_DISABLE_DIRECTORY_LISTING
    if (strcmp(opts->enable_directory_listing, "yes") == 0) {
      mg_send_directory_listing(nc, path, hm, opts);
    } else {
      mg_http_send_error(nc, 403, NULL);
    }
#else
    mg_http_send_error(nc, 501, NULL);
#endif
  } else if (mg_is_not_modified(hm, &st)) {
    mg_http_send_error(nc, 304, "Not Modified");
  } else {
    mg_http_serve_file2(nc, index_file ? index_file : path, hm, opts);
  }
  MG_FREE(index_file);
}

void mg_serve_http(struct mg_connection *nc, struct http_message *hm,
                   struct mg_serve_http_opts opts) {
  char *path = NULL;
  struct mg_str *hdr, path_info;
  uint32_t remote_ip = ntohl(*(uint32_t *) &nc->sa.sin.sin_addr);

  if (mg_check_ip_acl(opts.ip_acl, remote_ip) != 1) {
    /* Not allowed to connect */
    mg_http_send_error(nc, 403, NULL);
    nc->flags |= MG_F_SEND_AND_CLOSE;
    return;
  }

  if (mg_http_send_port_based_redirect(nc, hm, &opts)) {
    return;
  }

  if (opts.document_root == NULL) {
    opts.document_root = ".";
  }
  if (opts.per_directory_auth_file == NULL) {
    opts.per_directory_auth_file = ".htpasswd";
  }
  if (opts.enable_directory_listing == NULL) {
    opts.enable_directory_listing = "yes";
  }
  if (opts.cgi_file_pattern == NULL) {
    opts.cgi_file_pattern = "**.cgi$|**.php$";
  }
  if (opts.ssi_pattern == NULL) {
    opts.ssi_pattern = "**.shtml$|**.shtm$";
  }
  if (opts.index_files == NULL) {
    opts.index_files = "index.html,index.htm,index.shtml,index.cgi,index.php";
  }
  /* Normalize path - resolve "." and ".." (in-place). */
  if (!mg_normalize_uri_path(&hm->uri, &hm->uri)) {
    mg_http_send_error(nc, 400, NULL);
    return;
  }
  if (mg_uri_to_local_path(hm, &opts, &path, &path_info) == 0) {
    mg_http_send_error(nc, 404, NULL);
    return;
  }
  mg_send_http_file(nc, path, &path_info, hm, &opts);

  MG_FREE(path);
  path = NULL;

  /* Close connection for non-keep-alive requests */
  if (mg_vcmp(&hm->proto, "HTTP/1.1") != 0 ||
      ((hdr = mg_get_http_header(hm, "Connection")) != NULL &&
       mg_vcmp(hdr, "keep-alive") != 0)) {
#if 0
    nc->flags |= MG_F_SEND_AND_CLOSE;
#endif
  }
}

#endif /* MG_DISABLE_FILESYSTEM */

/* returns 0 on success, -1 on error */
static int mg_http_common_url_parse(const char *url, const char *schema,
                                    const char *schema_tls, int *use_ssl,
                                    char **addr, int *port_i,
                                    const char **path) {
  int addr_len = 0;

  if (memcmp(url, schema, strlen(schema)) == 0) {
    url += strlen(schema);
  } else if (memcmp(url, schema_tls, strlen(schema_tls)) == 0) {
    url += strlen(schema_tls);
    *use_ssl = 1;
#ifndef MG_ENABLE_SSL
    return -1; /* SSL is not enabled, cannot do HTTPS URLs */
#endif
  }

  while (*url != '\0') {
    *addr = (char *) MG_REALLOC(*addr, addr_len + 6 /* space for port too. */);
    if (*addr == NULL) {
      DBG(("OOM"));
      return -1;
    }
    if (*url == '/') {
      break;
    }
    if (*url == ':') *port_i = addr_len;
    (*addr)[addr_len++] = *url;
    (*addr)[addr_len] = '\0';
    url++;
  }
  if (addr_len == 0) goto cleanup;
  if (*port_i < 0) {
    *port_i = addr_len;
    strcpy(*addr + *port_i, *use_ssl ? ":443" : ":80");
  } else {
    *port_i = -1;
  }

  if (*path == NULL) *path = url;

  if (**path == '\0') *path = "/";

  DBG(("%s %s", *addr, *path));

  return 0;

cleanup:
  MG_FREE(*addr);
  return -1;
}

struct mg_connection *mg_connect_http_base(
    struct mg_mgr *mgr, mg_event_handler_t ev_handler,
    struct mg_connect_opts opts, const char *schema, const char *schema_ssl,
    const char *url, const char **path, char **addr) {
  struct mg_connection *nc = NULL;
  int port_i = -1;
  int use_ssl = 0;

  if (mg_http_common_url_parse(url, schema, schema_ssl, &use_ssl, addr, &port_i,
                               path) < 0) {
    return NULL;
  }

  LOG(LL_DEBUG, ("%s use_ssl? %d", url, use_ssl));
  if (use_ssl) {
#ifdef MG_ENABLE_SSL
    /*
     * Schema requires SSL, but no SSL parameters were provided in opts.
     * In order to maintain backward compatibility, use a faux-SSL with no
     * verification.
     */
    if (opts.ssl_ca_cert == NULL) {
      opts.ssl_ca_cert = "*";
    }
#else
    MG_SET_PTRPTR(opts.error_string, "ssl is disabled");
    MG_FREE(addr);
    return NULL;
#endif
  }

  if ((nc = mg_connect_opt(mgr, *addr, ev_handler, opts)) != NULL) {
    mg_set_protocol_http_websocket(nc);
    /* If the port was addred by us, restore the original host. */
    if (port_i >= 0) (*addr)[port_i] = '\0';
  }

  return nc;
}

struct mg_connection *mg_connect_http_opt(struct mg_mgr *mgr,
                                          mg_event_handler_t ev_handler,
                                          struct mg_connect_opts opts,
                                          const char *url,
                                          const char *extra_headers,
                                          const char *post_data) {
  char *addr = NULL;
  const char *path = NULL;
  struct mg_connection *nc = mg_connect_http_base(
      mgr, ev_handler, opts, "http://", "https://", url, &path, &addr);

  if (nc == NULL) {
    return NULL;
  }

  mg_printf(nc, "%s %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %" SIZE_T_FMT
                "\r\n%s\r\n%s",
            post_data == NULL ? "GET" : "POST", path, addr,
            post_data == NULL ? 0 : strlen(post_data),
            extra_headers == NULL ? "" : extra_headers,
            post_data == NULL ? "" : post_data);

  MG_FREE(addr);
  return nc;
}

struct mg_connection *mg_connect_http(struct mg_mgr *mgr,
                                      mg_event_handler_t ev_handler,
                                      const char *url,
                                      const char *extra_headers,
                                      const char *post_data) {
  struct mg_connect_opts opts;
  memset(&opts, 0, sizeof(opts));
  return mg_connect_http_opt(mgr, ev_handler, opts, url, extra_headers,
                             post_data);
}

#ifndef MG_DISABLE_HTTP_WEBSOCKET
struct mg_connection *mg_connect_ws_opt(struct mg_mgr *mgr,
                                        mg_event_handler_t ev_handler,
                                        struct mg_connect_opts opts,
                                        const char *url, const char *protocol,
                                        const char *extra_headers) {
  char *addr = NULL;
  const char *path = NULL;
  struct mg_connection *nc = mg_connect_http_base(
      mgr, ev_handler, opts, "ws://", "wss://", url, &path, &addr);

  if (nc != NULL) {
    mg_send_websocket_handshake2(nc, path, addr, protocol, extra_headers);
  }

  MG_FREE(addr);
  return nc;
}

struct mg_connection *mg_connect_ws(struct mg_mgr *mgr,
                                    mg_event_handler_t ev_handler,
                                    const char *url, const char *protocol,
                                    const char *extra_headers) {
  struct mg_connect_opts opts;
  memset(&opts, 0, sizeof(opts));
  return mg_connect_ws_opt(mgr, ev_handler, opts, url, protocol, extra_headers);
}
#endif /* MG_DISABLE_HTTP_WEBSOCKET */

size_t mg_parse_multipart(const char *buf, size_t buf_len, char *var_name,
                          size_t var_name_len, char *file_name,
                          size_t file_name_len, const char **data,
                          size_t *data_len) {
  static const char cd[] = "Content-Disposition: ";
  size_t hl, bl, n, ll, pos, cdl = sizeof(cd) - 1;

  if (buf == NULL || buf_len <= 0) return 0;
  if ((hl = mg_http_get_request_len(buf, buf_len)) <= 0) return 0;
  if (buf[0] != '-' || buf[1] != '-' || buf[2] == '\n') return 0;

  /* Get boundary length */
  bl = mg_get_line_len(buf, buf_len);

  /* Loop through headers, fetch variable name and file name */
  var_name[0] = file_name[0] = '\0';
  for (n = bl; (ll = mg_get_line_len(buf + n, hl - n)) > 0; n += ll) {
    if (mg_ncasecmp(cd, buf + n, cdl) == 0) {
      struct mg_str header;
      header.p = buf + n + cdl;
      header.len = ll - (cdl + 2);
      mg_http_parse_header(&header, "name", var_name, var_name_len);
      mg_http_parse_header(&header, "filename", file_name, file_name_len);
    }
  }

  /* Scan through the body, search for terminating boundary */
  for (pos = hl; pos + (bl - 2) < buf_len; pos++) {
    if (buf[pos] == '-' && !memcmp(buf, &buf[pos], bl - 2)) {
      if (data_len != NULL) *data_len = (pos - 2) - hl;
      if (data != NULL) *data = buf + hl;
      return pos;
    }
  }

  return 0;
}

void mg_register_http_endpoint(struct mg_connection *nc, const char *uri_path,
                               mg_event_handler_t handler) {
  struct mg_http_proto_data *pd = NULL;
  struct mg_http_endpoint *new_ep = NULL;

  if (nc == NULL) return;
  new_ep = (struct mg_http_endpoint *) calloc(1, sizeof(*new_ep));
  if (new_ep == NULL) return;

  pd = mg_http_get_proto_data(nc);
  new_ep->name = strdup(uri_path);
  new_ep->name_len = strlen(new_ep->name);
  new_ep->handler = handler;
  new_ep->next = pd->endpoints;
  pd->endpoints = new_ep;
}

#endif /* MG_DISABLE_HTTP */
