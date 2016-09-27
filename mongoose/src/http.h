/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

/*
 * === Common API reference
 */

#ifndef CS_MONGOOSE_SRC_HTTP_H_
#define CS_MONGOOSE_SRC_HTTP_H_

#include "mongoose/src/net.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef MG_MAX_HTTP_HEADERS
#define MG_MAX_HTTP_HEADERS 20
#endif

#ifndef MG_MAX_HTTP_REQUEST_SIZE
#define MG_MAX_HTTP_REQUEST_SIZE 1024
#endif

#ifndef MG_MAX_PATH
#ifdef PATH_MAX
#define MG_MAX_PATH PATH_MAX
#else
#define MG_MAX_PATH 256
#endif
#endif

#ifndef MG_MAX_HTTP_SEND_MBUF
#define MG_MAX_HTTP_SEND_MBUF 1024
#endif

#ifndef MG_WEBSOCKET_PING_INTERVAL_SECONDS
#define MG_WEBSOCKET_PING_INTERVAL_SECONDS 5
#endif

#ifndef MG_CGI_ENVIRONMENT_SIZE
#define MG_CGI_ENVIRONMENT_SIZE 8192
#endif

#ifndef MG_MAX_CGI_ENVIR_VARS
#define MG_MAX_CGI_ENVIR_VARS 64
#endif

#ifndef MG_ENV_EXPORT_TO_CGI
#define MG_ENV_EXPORT_TO_CGI "MONGOOSE_CGI"
#endif

/* HTTP message */
struct http_message {
  struct mg_str message; /* Whole message: request line + headers + body */

  /* HTTP Request line (or HTTP response line) */
  struct mg_str method; /* "GET" */
  struct mg_str uri;    /* "/my_file.html" */
  struct mg_str proto;  /* "HTTP/1.1" -- for both request and response */

  /* For responses, code and response status message are set */
  int resp_code;
  struct mg_str resp_status_msg;

  /*
   * Query-string part of the URI. For example, for HTTP request
   *    GET /foo/bar?param1=val1&param2=val2
   *    |    uri    |     query_string     |
   *
   * Note that question mark character doesn't belong neither to the uri,
   * nor to the query_string
   */
  struct mg_str query_string;

  /* Headers */
  struct mg_str header_names[MG_MAX_HTTP_HEADERS];
  struct mg_str header_values[MG_MAX_HTTP_HEADERS];

  /* Message body */
  struct mg_str body; /* Zero-length for requests with no body */
};

/* WebSocket message */
struct websocket_message {
  unsigned char *data;
  size_t size;
  unsigned char flags;
};

/* HTTP multipart part */
struct mg_http_multipart_part {
  const char *file_name;
  const char *var_name;
  struct mg_str data;
  int status; /* <0 on error */
  void *user_data;
};

/* HTTP and websocket events. void *ev_data is described in a comment. */
#define MG_EV_HTTP_REQUEST 100 /* struct http_message * */
#define MG_EV_HTTP_REPLY 101   /* struct http_message * */
#define MG_EV_HTTP_CHUNK 102   /* struct http_message * */
#define MG_EV_SSI_CALL 105     /* char * */

#ifndef MG_DISABLE_HTTP_WEBSOCKET
#define MG_EV_WEBSOCKET_HANDSHAKE_REQUEST 111 /* NULL */
#define MG_EV_WEBSOCKET_HANDSHAKE_DONE 112    /* NULL */
#define MG_EV_WEBSOCKET_FRAME 113             /* struct websocket_message * */
#define MG_EV_WEBSOCKET_CONTROL_FRAME 114     /* struct websocket_message * */
#endif

#ifdef MG_ENABLE_HTTP_STREAMING_MULTIPART
#define MG_EV_HTTP_MULTIPART_REQUEST 121 /* struct http_message */
#define MG_EV_HTTP_PART_BEGIN 122        /* struct mg_http_multipart_part */
#define MG_EV_HTTP_PART_DATA 123         /* struct mg_http_multipart_part */
#define MG_EV_HTTP_PART_END 124          /* struct mg_http_multipart_part */
#endif

/*
 * Attaches a built-in HTTP event handler to the given connection.
 * The user-defined event handler will receive following extra events:
 *
 * - MG_EV_HTTP_REQUEST: HTTP request has arrived. Parsed HTTP request
 *  is passed as
 *   `struct http_message` through the handler's `void *ev_data` pointer.
 * - MG_EV_HTTP_MULTIPART_REQUEST: A multipart POST request has received.
 *   This event is sent before body is parsed. After this, the user
 *   should expect a sequence of MG_EV_HTTP_PART_BEGIN/DATA/END requests.
 *   This is also the last time when headers and other request fields are
 *   accessible.
 * - MG_EV_HTTP_REPLY: The HTTP reply has arrived. The parsed HTTP reply is
 *   passed as `struct http_message` through the handler's `void *ev_data`
 *   pointer.
 * - MG_EV_HTTP_CHUNK: The HTTP chunked-encoding chunk has arrived.
 *   The parsed HTTP reply is passed as `struct http_message` through the
 *   handler's `void *ev_data` pointer. `http_message::body` would contain
 *   incomplete, reassembled HTTP body.
 *   It will grow with every new chunk that arrives, and it can
 *   potentially consume a lot of memory. An event handler may process
 *   the body as chunks are coming, and signal Mongoose to delete processed
 *   body by setting `MG_F_DELETE_CHUNK` in `mg_connection::flags`. When
 *   the last zero chunk is received,
 *   Mongoose sends `MG_EV_HTTP_REPLY` event with
 *   full reassembled body (if handler did not signal to delete chunks) or
 *   with empty body (if handler did signal to delete chunks).
 * - MG_EV_WEBSOCKET_HANDSHAKE_REQUEST: server has received the WebSocket
 *   handshake request. `ev_data` contains parsed HTTP request.
 * - MG_EV_WEBSOCKET_HANDSHAKE_DONE: server has completed the WebSocket
 *   handshake. `ev_data` is `NULL`.
 * - MG_EV_WEBSOCKET_FRAME: new WebSocket frame has arrived. `ev_data` is
 *   `struct websocket_message *`
 * - MG_EV_HTTP_PART_BEGIN: new part of multipart message is started,
 *   extra parameters are passed in mg_http_multipart_part
 * - MG_EV_HTTP_PART_DATA: new portion of data from the multiparted message
 *   no additional headers are available, only data and data size
 * - MG_EV_HTTP_PART_END: final boundary received, analogue to maybe used to
 *   find the end of packet
 *   Note: Mongoose should be compiled with MG_ENABLE_HTTP_STREAMING_MULTIPART
 *   to enable MG_EV_HTTP_MULTIPART_REQUEST, MG_EV_HTTP_REQUEST_END,
 *   MG_EV_HTTP_REQUEST_CANCEL, MG_EV_HTTP_PART_BEGIN, MG_EV_HTTP_PART_DATA,
 *   MG_EV_HTTP_PART_END constants
 */
void mg_set_protocol_http_websocket(struct mg_connection *nc);

#ifndef MG_DISABLE_HTTP_WEBSOCKET
/*
 * Send websocket handshake to the server.
 *
 * `nc` must be a valid connection, connected to a server. `uri` is an URI
 * to fetch, extra_headers` is extra HTTP headers to send or `NULL`.
 *
 * This function is intended to be used by websocket client.
 *
 * Note that the Host header is mandatory in HTTP/1.1 and must be
 * included in `extra_headers`. `mg_send_websocket_handshake2` offers
 * a better API for that.
 *
 * Deprecated in favour of `mg_send_websocket_handshake2`
 */
void mg_send_websocket_handshake(struct mg_connection *nc, const char *uri,
                                 const char *extra_headers);

/*
 * Send websocket handshake to the server.
 *
 * `nc` must be a valid connection, connected to a server. `uri` is an URI
 * to fetch, `host` goes into the `Host` header, `protocol` goes into the
 * `Sec-WebSocket-Proto` header (NULL to omit), extra_headers` is extra HTTP
 * headers to send or `NULL`.
 *
 * This function is intended to be used by websocket client.
 */
void mg_send_websocket_handshake2(struct mg_connection *nc, const char *path,
                                  const char *host, const char *protocol,
                                  const char *extra_headers);

/*
 * Helper function that creates an outbound WebSocket connection.
 *
 * `url` is a URL to connect to. It must be properly URL-encoded, e.g. have
 * no spaces, etc. By default, `mg_connect_ws()` sends Connection and
 * Host headers. `extra_headers` is an extra HTTP header to send, e.g.
 * `"User-Agent: my-app\r\n"`.
 * If `protocol` is not NULL, then a `Sec-WebSocket-Protocol` header is sent.
 *
 * Examples:
 *
 * ```c
 *   nc1 = mg_connect_ws(mgr, ev_handler_1, "ws://echo.websocket.org", NULL,
 *                       NULL);
 *   nc2 = mg_connect_ws(mgr, ev_handler_1, "wss://echo.websocket.org", NULL,
 *                       NULL);
 *   nc3 = mg_connect_ws(mgr, ev_handler_1, "ws://api.cesanta.com",
 *                       "clubby.cesanta.com", NULL);
 * ```
 */
struct mg_connection *mg_connect_ws(struct mg_mgr *mgr,
                                    mg_event_handler_t event_handler,
                                    const char *url, const char *protocol,
                                    const char *extra_headers);

/*
 * Helper function that creates an outbound WebSocket connection
 *
 * Mostly identical to `mg_connect_ws`, but allows to provide extra parameters
 * (for example, SSL parameters)
 */
struct mg_connection *mg_connect_ws_opt(struct mg_mgr *mgr,
                                        mg_event_handler_t ev_handler,
                                        struct mg_connect_opts opts,
                                        const char *url, const char *protocol,
                                        const char *extra_headers);

/*
 * Send WebSocket frame to the remote end.
 *
 * `op_and_flags` specifies the frame's type. It's one of:
 *
 * - WEBSOCKET_OP_CONTINUE
 * - WEBSOCKET_OP_TEXT
 * - WEBSOCKET_OP_BINARY
 * - WEBSOCKET_OP_CLOSE
 * - WEBSOCKET_OP_PING
 * - WEBSOCKET_OP_PONG
 *
 * Orred with one of the flags:
 *
 * - WEBSOCKET_DONT_FIN: Don't set the FIN flag on the frame to be sent.
 *
 * `data` and `data_len` contain frame data.
 */
void mg_send_websocket_frame(struct mg_connection *nc, int op_and_flags,
                             const void *data, size_t data_len);

/*
 * Sends multiple websocket frames.
 *
 * Like `mg_send_websocket_frame()`, but composes a frame from multiple buffers.
 */
void mg_send_websocket_framev(struct mg_connection *nc, int op_and_flags,
                              const struct mg_str *strings, int num_strings);

/*
 * Sends WebSocket frame to the remote end.
 *
 * Like `mg_send_websocket_frame()`, but allows to create formatted messages
 * with `printf()`-like semantics.
 */
void mg_printf_websocket_frame(struct mg_connection *nc, int op_and_flags,
                               const char *fmt, ...);
#endif /* MG_DISABLE_HTTP_WEBSOCKET */

/* Websocket opcodes, from http://tools.ietf.org/html/rfc6455 */
#define WEBSOCKET_OP_CONTINUE 0
#define WEBSOCKET_OP_TEXT 1
#define WEBSOCKET_OP_BINARY 2
#define WEBSOCKET_OP_CLOSE 8
#define WEBSOCKET_OP_PING 9
#define WEBSOCKET_OP_PONG 10

/*
 * If set causes the FIN flag to not be set on outbound
 * frames. This enables sending multiple fragments of a single
 * logical message.
 *
 * The WebSocket protocol mandates that if the FIN flag of a data
 * frame is not set, the next frame must be a WEBSOCKET_OP_CONTINUE.
 * The last frame must have the FIN bit set.
 *
 * Note that mongoose will automatically defragment incoming messages,
 * so this flag is used only on outbound messages.
 */
#define WEBSOCKET_DONT_FIN 0x100

/*
 * Decodes a URL-encoded string.
 *
 * Source string is specified by (`src`, `src_len`), and destination is
 * (`dst`, `dst_len`). If `is_form_url_encoded` is non-zero, then
 * `+` character is decoded as a blank space character. This function
 * guarantees to NUL-terminate the destination. If destination is too small,
 * then the source string is partially decoded and `-1` is returned. Otherwise,
 * a length of the decoded string is returned, not counting final NUL.
 */
int mg_url_decode(const char *src, int src_len, char *dst, int dst_len,
                  int is_form_url_encoded);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* CS_MONGOOSE_SRC_HTTP_H_ */
