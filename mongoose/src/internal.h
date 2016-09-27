/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#ifndef CS_MONGOOSE_SRC_INTERNAL_H_
#define CS_MONGOOSE_SRC_INTERNAL_H_

#ifndef MG_MALLOC
#define MG_MALLOC malloc
#endif

#ifndef MG_CALLOC
#define MG_CALLOC calloc
#endif

#ifndef MG_REALLOC
#define MG_REALLOC realloc
#endif

#ifndef MG_FREE
#define MG_FREE free
#endif

#ifndef MBUF_REALLOC
#define MBUF_REALLOC MG_REALLOC
#endif

#ifndef MBUF_FREE
#define MBUF_FREE MG_FREE
#endif

#define MG_SET_PTRPTR(_ptr, _v) \
  do {                          \
    if (_ptr) *(_ptr) = _v;     \
  } while (0)

#ifndef MG_INTERNAL
#define MG_INTERNAL static
#endif

#ifdef PICOTCP
#define NO_LIBC
#define MG_DISABLE_FILESYSTEM
#define MG_DISABLE_POPEN
#define MG_DISABLE_CGI
#define MG_DISABLE_DIRECTORY_LISTING
#define MG_DISABLE_SOCKETPAIR
#define MG_DISABLE_PFS
#endif

#include "mongoose/src/net.h"
#include "mongoose/src/http.h"
#include "common/cs_dbg.h"

#define MG_CTL_MSG_MESSAGE_SIZE 8192

/* internals that need to be accessible in unit tests */
MG_INTERNAL struct mg_connection *mg_do_connect(struct mg_connection *nc,
                                                int proto,
                                                union socket_address *sa);

MG_INTERNAL int mg_parse_address(const char *str, union socket_address *sa,
                                 int *proto, char *host, size_t host_len);
MG_INTERNAL void mg_call(struct mg_connection *nc,
                         mg_event_handler_t ev_handler, int ev, void *ev_data);
void mg_forward(struct mg_connection *from, struct mg_connection *to);
MG_INTERNAL void mg_add_conn(struct mg_mgr *mgr, struct mg_connection *c);
MG_INTERNAL void mg_remove_conn(struct mg_connection *c);
MG_INTERNAL struct mg_connection *mg_create_connection(
    struct mg_mgr *mgr, mg_event_handler_t callback,
    struct mg_add_sock_opts opts);
#ifndef MG_DISABLE_FILESYSTEM
MG_INTERNAL int mg_uri_to_local_path(struct http_message *hm,
                                     const struct mg_serve_http_opts *opts,
                                     char **local_path,
                                     struct mg_str *remainder);
#endif
#ifdef _WIN32
/* Retur value is the same as for MultiByteToWideChar. */
int to_wchar(const char *path, wchar_t *wbuf, size_t wbuf_len);
#endif

/*
 * Reassemble the content of the buffer (buf, blen) which should be
 * in the HTTP chunked encoding, by collapsing data chunks to the
 * beginning of the buffer.
 *
 * If chunks get reassembled, modify hm->body to point to the reassembled
 * body and fire MG_EV_HTTP_CHUNK event. If handler sets MG_F_DELETE_CHUNK
 * in nc->flags, delete reassembled body from the mbuf.
 *
 * Return reassembled body size.
 */
MG_INTERNAL size_t mg_handle_chunked(struct mg_connection *nc,
                                     struct http_message *hm, char *buf,
                                     size_t blen);

#ifndef MG_DISABLE_FILESYSTEM
MG_INTERNAL time_t mg_parse_date_string(const char *datetime);
MG_INTERNAL int mg_is_not_modified(struct http_message *hm, cs_stat_t *st);
#endif

struct ctl_msg {
  mg_event_handler_t callback;
  char message[MG_CTL_MSG_MESSAGE_SIZE];
};

#ifndef MG_DISABLE_MQTT
struct mg_mqtt_message;
MG_INTERNAL int parse_mqtt(struct mbuf *io, struct mg_mqtt_message *mm);
#endif

/* Forward declarations for testing. */
extern void *(*test_malloc)(size_t size);
extern void *(*test_calloc)(size_t count, size_t size);

#endif /* CS_MONGOOSE_SRC_INTERNAL_H_ */
