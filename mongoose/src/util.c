/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#include "common/base64.h"
#include "mongoose/src/internal.h"
#include "mongoose/src/util.h"

const char *mg_skip(const char *s, const char *end, const char *delims,
                    struct mg_str *v) {
  v->p = s;
  while (s < end && strchr(delims, *(unsigned char *) s) == NULL) s++;
  v->len = s - v->p;
  while (s < end && strchr(delims, *(unsigned char *) s) != NULL) s++;
  return s;
}

static int lowercase(const char *s) {
  return tolower(*(const unsigned char *) s);
}

int mg_ncasecmp(const char *s1, const char *s2, size_t len) {
  int diff = 0;

  if (len > 0) do {
      diff = lowercase(s1++) - lowercase(s2++);
    } while (diff == 0 && s1[-1] != '\0' && --len > 0);

  return diff;
}

int mg_casecmp(const char *s1, const char *s2) {
  return mg_ncasecmp(s1, s2, (size_t) ~0);
}

#ifndef MG_DISABLE_FILESYSTEM
int mg_stat(const char *path, cs_stat_t *st) {
#ifdef _WIN32
  wchar_t wpath[MAX_PATH_SIZE];
  to_wchar(path, wpath, ARRAY_SIZE(wpath));
  DBG(("[%ls] -> %d", wpath, _wstati64(wpath, st)));
  return _wstati64(wpath, (struct _stati64 *) st);
#else
  return stat(path, st);
#endif
}

FILE *mg_fopen(const char *path, const char *mode) {
#ifdef _WIN32
  wchar_t wpath[MAX_PATH_SIZE], wmode[10];
  to_wchar(path, wpath, ARRAY_SIZE(wpath));
  to_wchar(mode, wmode, ARRAY_SIZE(wmode));
  return _wfopen(wpath, wmode);
#else
  return fopen(path, mode);
#endif
}

int mg_open(const char *path, int flag, int mode) { /* LCOV_EXCL_LINE */
#ifdef _WIN32
  wchar_t wpath[MAX_PATH_SIZE];
  to_wchar(path, wpath, ARRAY_SIZE(wpath));
  return _wopen(wpath, flag, mode);
#else
  return open(path, flag, mode); /* LCOV_EXCL_LINE */
#endif
}
#endif

void mg_base64_encode(const unsigned char *src, int src_len, char *dst) {
  cs_base64_encode(src, src_len, dst);
}

int mg_base64_decode(const unsigned char *s, int len, char *dst) {
  return cs_base64_decode(s, len, dst);
}

#ifdef MG_ENABLE_THREADS
void *mg_start_thread(void *(*f)(void *), void *p) {
#ifdef _WIN32
  return (void *) _beginthread((void(__cdecl *) (void *) ) f, 0, p);
#else
  pthread_t thread_id = (pthread_t) 0;
  pthread_attr_t attr;

  (void) pthread_attr_init(&attr);
  (void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

#if defined(MG_STACK_SIZE) && MG_STACK_SIZE > 1
  (void) pthread_attr_setstacksize(&attr, MG_STACK_SIZE);
#endif

  pthread_create(&thread_id, &attr, f, p);
  pthread_attr_destroy(&attr);

  return (void *) thread_id;
#endif
}
#endif /* MG_ENABLE_THREADS */

/* Set close-on-exec bit for a given socket. */
void mg_set_close_on_exec(sock_t sock) {
#ifdef _WIN32
  (void) SetHandleInformation((HANDLE) sock, HANDLE_FLAG_INHERIT, 0);
#elif defined(__unix__)
  fcntl(sock, F_SETFD, FD_CLOEXEC);
#else
  (void) sock;
#endif
}

void mg_sock_addr_to_str(const union socket_address *sa, char *buf, size_t len,
                         int flags) {
  int is_v6;
  if (buf == NULL || len <= 0) return;
  buf[0] = '\0';
#if defined(MG_ENABLE_IPV6)
  is_v6 = sa->sa.sa_family == AF_INET6;
#else
  is_v6 = 0;
#endif
  if (flags & MG_SOCK_STRINGIFY_IP) {
#if defined(MG_ENABLE_IPV6)
    const void *addr = NULL;
    char *start = buf;
    socklen_t capacity = len;
    if (!is_v6) {
      addr = &sa->sin.sin_addr;
    } else {
      addr = (void *) &sa->sin6.sin6_addr;
      if (flags & MG_SOCK_STRINGIFY_PORT) {
        *buf = '[';
        start++;
        capacity--;
      }
    }
    if (inet_ntop(sa->sa.sa_family, addr, start, capacity) == NULL) {
      *buf = '\0';
    }
#elif defined(_WIN32) || defined(MG_LWIP)
    /* Only Windoze Vista (and newer) have inet_ntop() */
    strncpy(buf, inet_ntoa(sa->sin.sin_addr), len);
#else
    inet_ntop(AF_INET, (void *) &sa->sin.sin_addr, buf, len);
#endif
  }
  if (flags & MG_SOCK_STRINGIFY_PORT) {
    int port = ntohs(sa->sin.sin_port);
    if (flags & MG_SOCK_STRINGIFY_IP) {
      snprintf(buf + strlen(buf), len - (strlen(buf) + 1), "%s:%d",
               (is_v6 ? "]" : ""), port);
    } else {
      snprintf(buf, len, "%d", port);
    }
  }
}

void mg_conn_addr_to_str(struct mg_connection *nc, char *buf, size_t len,
                         int flags) {
  union socket_address sa;
  memset(&sa, 0, sizeof(sa));
  mg_if_get_conn_addr(nc, flags & MG_SOCK_STRINGIFY_REMOTE, &sa);
  mg_sock_addr_to_str(&sa, buf, len, flags);
}

#ifndef MG_DISABLE_HEXDUMP
int mg_hexdump(const void *buf, int len, char *dst, int dst_len) {
  const unsigned char *p = (const unsigned char *) buf;
  char ascii[17] = "";
  int i, idx, n = 0;

  for (i = 0; i < len; i++) {
    idx = i % 16;
    if (idx == 0) {
      if (i > 0) n += snprintf(dst + n, dst_len - n, "  %s\n", ascii);
      n += snprintf(dst + n, dst_len - n, "%04x ", i);
    }
    n += snprintf(dst + n, dst_len - n, " %02x", p[i]);
    ascii[idx] = p[i] < 0x20 || p[i] > 0x7e ? '.' : p[i];
    ascii[idx + 1] = '\0';
  }

  while (i++ % 16) n += snprintf(dst + n, dst_len - n, "%s", "   ");
  n += snprintf(dst + n, dst_len - n, "  %s\n\n", ascii);

  return n;
}
#endif

int mg_avprintf(char **buf, size_t size, const char *fmt, va_list ap) {
  va_list ap_copy;
  int len;

  va_copy(ap_copy, ap);
  len = vsnprintf(*buf, size, fmt, ap_copy);
  va_end(ap_copy);

  if (len < 0) {
    /* eCos and Windows are not standard-compliant and return -1 when
     * the buffer is too small. Keep allocating larger buffers until we
     * succeed or out of memory. */
    *buf = NULL; /* LCOV_EXCL_START */
    while (len < 0) {
      MG_FREE(*buf);
      size *= 2;
      if ((*buf = (char *) MG_MALLOC(size)) == NULL) break;
      va_copy(ap_copy, ap);
      len = vsnprintf(*buf, size, fmt, ap_copy);
      va_end(ap_copy);
    }
    /* LCOV_EXCL_STOP */
  } else if (len >= (int) size) {
    /* Standard-compliant code path. Allocate a buffer that is large enough. */
    if ((*buf = (char *) MG_MALLOC(len + 1)) == NULL) {
      len = -1; /* LCOV_EXCL_LINE */
    } else {    /* LCOV_EXCL_LINE */
      va_copy(ap_copy, ap);
      len = vsnprintf(*buf, len + 1, fmt, ap_copy);
      va_end(ap_copy);
    }
  }

  return len;
}

#if !defined(MG_DISABLE_HEXDUMP)
void mg_hexdump_connection(struct mg_connection *nc, const char *path,
                           const void *buf, int num_bytes, int ev) {
#if !defined(NO_LIBC) && !defined(MG_DISABLE_STDIO)
  FILE *fp = NULL;
  char *hexbuf, src[60], dst[60];
  int buf_size = num_bytes * 5 + 100;

  if (strcmp(path, "-") == 0) {
    fp = stdout;
  } else if (strcmp(path, "--") == 0) {
    fp = stderr;
#ifndef MG_DISABLE_FILESYSTEM
  } else {
    fp = fopen(path, "a");
#endif
  }
  if (fp == NULL) return;

  mg_conn_addr_to_str(nc, src, sizeof(src),
                      MG_SOCK_STRINGIFY_IP | MG_SOCK_STRINGIFY_PORT);
  mg_conn_addr_to_str(nc, dst, sizeof(dst), MG_SOCK_STRINGIFY_IP |
                                                MG_SOCK_STRINGIFY_PORT |
                                                MG_SOCK_STRINGIFY_REMOTE);
  fprintf(
      fp, "%lu %p %s %s %s %d\n", (unsigned long) time(NULL), (void *) nc, src,
      ev == MG_EV_RECV ? "<-" : ev == MG_EV_SEND
                                    ? "->"
                                    : ev == MG_EV_ACCEPT
                                          ? "<A"
                                          : ev == MG_EV_CONNECT ? "C>" : "XX",
      dst, num_bytes);
  if (num_bytes > 0 && (hexbuf = (char *) MG_MALLOC(buf_size)) != NULL) {
    mg_hexdump(buf, num_bytes, hexbuf, buf_size);
    fprintf(fp, "%s", hexbuf);
    MG_FREE(hexbuf);
  }
  if (fp != stdin && fp != stdout) fclose(fp);
#endif
}
#endif

int mg_is_big_endian(void) {
  static const int n = 1;
  /* TODO(mkm) use compiletime check with 4-byte char literal */
  return ((char *) &n)[0] == 0;
}

const char *mg_next_comma_list_entry(const char *list, struct mg_str *val,
                                     struct mg_str *eq_val) {
  if (list == NULL || *list == '\0') {
    /* End of the list */
    list = NULL;
  } else {
    val->p = list;
    if ((list = strchr(val->p, ',')) != NULL) {
      /* Comma found. Store length and shift the list ptr */
      val->len = list - val->p;
      list++;
    } else {
      /* This value is the last one */
      list = val->p + strlen(val->p);
      val->len = list - val->p;
    }

    if (eq_val != NULL) {
      /* Value has form "x=y", adjust pointers and lengths */
      /* so that val points to "x", and eq_val points to "y". */
      eq_val->len = 0;
      eq_val->p = (const char *) memchr(val->p, '=', val->len);
      if (eq_val->p != NULL) {
        eq_val->p++; /* Skip over '=' character */
        eq_val->len = val->p + val->len - eq_val->p;
        val->len = (eq_val->p - val->p) - 1;
      }
    }
  }

  return list;
}

int mg_match_prefix_n(const struct mg_str pattern, const struct mg_str str) {
  const char *or_str;
  size_t len, i = 0, j = 0;
  int res;

  if ((or_str = (const char *) memchr(pattern.p, '|', pattern.len)) != NULL) {
    struct mg_str pstr = {pattern.p, (size_t)(or_str - pattern.p)};
    res = mg_match_prefix_n(pstr, str);
    if (res > 0) return res;
    pstr.p = or_str + 1;
    pstr.len = (pattern.p + pattern.len) - (or_str + 1);
    return mg_match_prefix_n(pstr, str);
  }

  for (; i < pattern.len; i++, j++) {
    if (pattern.p[i] == '?' && j != str.len) {
      continue;
    } else if (pattern.p[i] == '$') {
      return j == str.len ? (int) j : -1;
    } else if (pattern.p[i] == '*') {
      i++;
      if (pattern.p[i] == '*') {
        i++;
        len = str.len - j;
      } else {
        len = 0;
        while (j + len != str.len && str.p[len] != '/') {
          len++;
        }
      }
      if (i == pattern.len) {
        return j + len;
      }
      do {
        const struct mg_str pstr = {pattern.p + i, pattern.len - i};
        const struct mg_str sstr = {str.p + j + len, str.len - j - len};
        res = mg_match_prefix_n(pstr, sstr);
      } while (res == -1 && len-- > 0);
      return res == -1 ? -1 : (int) (j + res + len);
    } else if (lowercase(&pattern.p[i]) != lowercase(&str.p[j])) {
      return -1;
    }
  }
  return j;
}

int mg_match_prefix(const char *pattern, int pattern_len, const char *str) {
  const struct mg_str pstr = {pattern, (size_t) pattern_len};
  return mg_match_prefix_n(pstr, mg_mk_str(str));
}
