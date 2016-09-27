/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#include "mongoose/src/internal.h"
#include "mongoose/src/uri.h"

/*
 * scan string until `sep`, keeping track of component boundaries in `res`.
 *
 * `p` will point to the char after the separator or it will be `end`.
 */
static void parse_uri_component(const char **p, const char *end, char sep,
                                struct mg_str *res) {
  res->p = *p;
  for (; *p < end; (*p)++) {
    if (**p == sep) {
      break;
    }
  }
  res->len = (*p) - res->p;
  if (*p < end) (*p)++;
}

int mg_parse_uri(struct mg_str uri, struct mg_str *scheme,
                 struct mg_str *user_info, struct mg_str *host,
                 unsigned int *port, struct mg_str *path, struct mg_str *query,
                 struct mg_str *fragment) {
  struct mg_str rscheme = {0, 0}, ruser_info = {0, 0}, rhost = {0, 0},
                rpath = {0, 0}, rquery = {0, 0}, rfragment = {0, 0};
  unsigned int rport = 0;
  enum {
    P_START,
    P_SCHEME_OR_PORT,
    P_USER_INFO,
    P_HOST,
    P_PORT,
    P_REST
  } state = P_START;

  const char *p = uri.p, *end = p + uri.len;
  while (p < end) {
    switch (state) {
      case P_START:
        /*
         * expecting on of:
         * - `scheme://xxxx`
         * - `xxxx:port`
         * - `xxxx/path`
         */
        for (; p < end; p++) {
          if (*p == ':') {
            state = P_SCHEME_OR_PORT;
            break;
          } else if (*p == '/') {
            state = P_REST;
            break;
          }
        }
        if (state == P_START || state == P_REST) {
          rhost.p = uri.p;
          rhost.len = p - uri.p;
        }
        break;
      case P_SCHEME_OR_PORT:
        if (end - p >= 3 && memcmp(p, "://", 3) == 0) {
          rscheme.p = uri.p;
          rscheme.len = p - uri.p;
          state = P_USER_INFO;
          p += 2; /* point to last separator char */
        } else {
          rhost.p = uri.p;
          rhost.len = p - uri.p;
          state = P_PORT;
        }
        break;
      case P_USER_INFO:
        p++;
        ruser_info.p = p;
        for (; p < end; p++) {
          if (*p == '@') {
            state = P_HOST;
            break;
          } else if (*p == '/') {
            break;
          }
        }
        if (p == end || *p == '/') {
          /* backtrack and parse as host */
          state = P_HOST;
          p = ruser_info.p;
        }
        ruser_info.len = p - ruser_info.p;
        break;
      case P_HOST:
        if (*p == '@') p++;
        rhost.p = p;
        for (; p < end; p++) {
          if (*p == ':') {
            state = P_PORT;
            break;
          } else if (*p == '/') {
            state = P_REST;
            break;
          }
        }
        rhost.len = p - rhost.p;
        break;
      case P_PORT:
        p++;
        for (; p < end; p++) {
          if (*p == '/') {
            state = P_REST;
            break;
          }
          rport *= 10;
          rport += *p - '0';
        }
        break;
      case P_REST:
        /* `p` points to separator. `path` includes the separator */
        parse_uri_component(&p, end, '?', &rpath);
        parse_uri_component(&p, end, '#', &rquery);
        parse_uri_component(&p, end, '\0', &rfragment);
        break;
    }
  }

  if (scheme != 0) *scheme = rscheme;
  if (user_info != 0) *user_info = ruser_info;
  if (host != 0) *host = rhost;
  if (port != 0) *port = rport;
  if (path != 0) *path = rpath;
  if (query != 0) *query = rquery;
  if (fragment != 0) *fragment = rfragment;

  return 0;
}

/* Normalize the URI path. Remove/resolve "." and "..". */
int mg_normalize_uri_path(const struct mg_str *in, struct mg_str *out) {
  const char *s = in->p, *se = s + in->len;
  char *cp = (char *) out->p, *d;

  if (in->len == 0 || *s != '/') {
    out->len = 0;
    return 0;
  }

  d = cp;

  while (s < se) {
    const char *next = s;
    struct mg_str component;
    parse_uri_component(&next, se, '/', &component);
    if (mg_vcmp(&component, ".") == 0) {
      /* Yum. */
    } else if (mg_vcmp(&component, "..") == 0) {
      /* Backtrack to previous slash. */
      if (d > cp + 1 && *(d - 1) == '/') d--;
      while (d > cp && *(d - 1) != '/') d--;
    } else {
      memmove(d, s, next - s);
      d += next - s;
    }
    s = next;
  }
  if (d == cp) *d++ = '/';

  out->p = cp;
  out->len = d - cp;
  return 1;
}
