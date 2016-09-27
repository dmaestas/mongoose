/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#ifndef MG_DISABLE_RESOLVER

#include "mongoose/src/internal.h"
#include "mongoose/src/resolv.h"

#ifndef MG_DEFAULT_NAMESERVER
#define MG_DEFAULT_NAMESERVER "8.8.8.8"
#endif

static const char *mg_default_dns_server = "udp://" MG_DEFAULT_NAMESERVER ":53";

MG_INTERNAL char mg_dns_server[256];

struct mg_resolve_async_request {
  char name[1024];
  int query;
  mg_resolve_callback_t callback;
  void *data;
  time_t timeout;
  int max_retries;
  enum mg_resolve_err err;

  /* state */
  time_t last_time;
  int retries;
};

/*
 * Find what nameserver to use.
 *
 * Return 0 if OK, -1 if error
 */
static int mg_get_ip_address_of_nameserver(char *name, size_t name_len) {
  int ret = -1;

#ifdef _WIN32
  int i;
  LONG err;
  HKEY hKey, hSub;
  char subkey[512], value[128],
      *key = "SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces";

  if ((err = RegOpenKeyA(HKEY_LOCAL_MACHINE, key, &hKey)) != ERROR_SUCCESS) {
    fprintf(stderr, "cannot open reg key %s: %ld\n", key, err);
    ret = -1;
  } else {
    for (ret = -1, i = 0;
         RegEnumKeyA(hKey, i, subkey, sizeof(subkey)) == ERROR_SUCCESS; i++) {
      DWORD type, len = sizeof(value);
      if (RegOpenKeyA(hKey, subkey, &hSub) == ERROR_SUCCESS &&
          (RegQueryValueExA(hSub, "NameServer", 0, &type, (void *) value,
                            &len) == ERROR_SUCCESS ||
           RegQueryValueExA(hSub, "DhcpNameServer", 0, &type, (void *) value,
                            &len) == ERROR_SUCCESS)) {
        /*
         * See https://github.com/cesanta/mongoose/issues/176
         * The value taken from the registry can be empty, a single
         * IP address, or multiple IP addresses separated by comma.
         * If it's empty, check the next interface.
         * If it's multiple IP addresses, take the first one.
         */
        char *comma = strchr(value, ',');
        if (value[0] == '\0') {
          continue;
        }
        if (comma != NULL) {
          *comma = '\0';
        }
        snprintf(name, name_len, "udp://%s:53", value);
        ret = 0;
        RegCloseKey(hSub);
        break;
      }
    }
    RegCloseKey(hKey);
  }
#elif !defined(MG_DISABLE_FILESYSTEM)
  FILE *fp;
  char line[512];

  if ((fp = fopen("/etc/resolv.conf", "r")) == NULL) {
    ret = -1;
  } else {
    /* Try to figure out what nameserver to use */
    for (ret = -1; fgets(line, sizeof(line), fp) != NULL;) {
      char buf[256];
      if (sscanf(line, "nameserver %255[^\n\t #]s", buf) == 1) {
        snprintf(name, name_len, "udp://%s:53", buf);
        ret = 0;
        break;
      }
    }
    (void) fclose(fp);
  }
#else
  snprintf(name, name_len, "%s", mg_default_dns_server);
#endif /* _WIN32 */

  return ret;
}

int mg_resolve_from_hosts_file(const char *name, union socket_address *usa) {
#ifndef MG_DISABLE_FILESYSTEM
  /* TODO(mkm) cache /etc/hosts */
  FILE *fp;
  char line[1024];
  char *p;
  char alias[256];
  unsigned int a, b, c, d;
  int len = 0;

  if ((fp = fopen("/etc/hosts", "r")) == NULL) {
    return -1;
  }

  for (; fgets(line, sizeof(line), fp) != NULL;) {
    if (line[0] == '#') continue;

    if (sscanf(line, "%u.%u.%u.%u%n", &a, &b, &c, &d, &len) == 0) {
      /* TODO(mkm): handle ipv6 */
      continue;
    }
    for (p = line + len; sscanf(p, "%s%n", alias, &len) == 1; p += len) {
      if (strcmp(alias, name) == 0) {
        usa->sin.sin_addr.s_addr = htonl(a << 24 | b << 16 | c << 8 | d);
        fclose(fp);
        return 0;
      }
    }
  }

  fclose(fp);
#endif

  return -1;
}

static void mg_resolve_async_eh(struct mg_connection *nc, int ev, void *data) {
  time_t now = time(NULL);
  struct mg_resolve_async_request *req;
  struct mg_dns_message *msg;

  DBG(("ev=%d user_data=%p", ev, nc->user_data));

  req = (struct mg_resolve_async_request *) nc->user_data;

  if (req == NULL) {
    return;
  }

  switch (ev) {
    case MG_EV_CONNECT:
    case MG_EV_POLL:
      if (req->retries > req->max_retries) {
        req->err = MG_RESOLVE_EXCEEDED_RETRY_COUNT;
        nc->flags |= MG_F_CLOSE_IMMEDIATELY;
        break;
      }
      if (now - req->last_time >= req->timeout) {
        mg_send_dns_query(nc, req->name, req->query);
        req->last_time = now;
        req->retries++;
      }
      break;
    case MG_EV_RECV:
      msg = (struct mg_dns_message *) MG_MALLOC(sizeof(*msg));
      if (mg_parse_dns(nc->recv_mbuf.buf, *(int *) data, msg) == 0 &&
          msg->num_answers > 0) {
        req->callback(msg, req->data, MG_RESOLVE_OK);
        nc->user_data = NULL;
        MG_FREE(req);
      } else {
        req->err = MG_RESOLVE_NO_ANSWERS;
      }
      MG_FREE(msg);
      nc->flags |= MG_F_CLOSE_IMMEDIATELY;
      break;
    case MG_EV_SEND:
      /*
       * If a send error occurs, prevent closing of the connection by the core.
       * We will retry after timeout.
       */
      nc->flags &= ~MG_F_CLOSE_IMMEDIATELY;
      mbuf_remove(&nc->send_mbuf, nc->send_mbuf.len);
      break;
    case MG_EV_TIMER:
      req->err = MG_RESOLVE_TIMEOUT;
      nc->flags |= MG_F_CLOSE_IMMEDIATELY;
      break;
    case MG_EV_CLOSE:
      /* If we got here with request still not done, fire an error callback. */
      if (req != NULL) {
        req->callback(NULL, req->data, req->err);
        nc->user_data = NULL;
        MG_FREE(req);
      }
      break;
  }
}

int mg_resolve_async(struct mg_mgr *mgr, const char *name, int query,
                     mg_resolve_callback_t cb, void *data) {
  struct mg_resolve_async_opts opts;
  memset(&opts, 0, sizeof(opts));
  return mg_resolve_async_opt(mgr, name, query, cb, data, opts);
}

int mg_resolve_async_opt(struct mg_mgr *mgr, const char *name, int query,
                         mg_resolve_callback_t cb, void *data,
                         struct mg_resolve_async_opts opts) {
  struct mg_resolve_async_request *req;
  struct mg_connection *dns_nc;
  const char *nameserver = opts.nameserver_url;

  DBG(("%s %d %p", name, query, opts.dns_conn));

  /* resolve with DNS */
  req = (struct mg_resolve_async_request *) MG_CALLOC(1, sizeof(*req));
  if (req == NULL) {
    return -1;
  }

  strncpy(req->name, name, sizeof(req->name));
  req->query = query;
  req->callback = cb;
  req->data = data;
  /* TODO(mkm): parse defaults out of resolve.conf */
  req->max_retries = opts.max_retries ? opts.max_retries : 2;
  req->timeout = opts.timeout ? opts.timeout : 5;

  /* Lazily initialize dns server */
  if (nameserver == NULL && mg_dns_server[0] == '\0' &&
      mg_get_ip_address_of_nameserver(mg_dns_server, sizeof(mg_dns_server)) ==
          -1) {
    strncpy(mg_dns_server, mg_default_dns_server, sizeof(mg_dns_server));
  }

  if (nameserver == NULL) {
    nameserver = mg_dns_server;
  }

  dns_nc = mg_connect(mgr, nameserver, mg_resolve_async_eh);
  if (dns_nc == NULL) {
    free(req);
    return -1;
  }
  dns_nc->user_data = req;
  if (opts.dns_conn != NULL) {
    *opts.dns_conn = dns_nc;
  }

  return 0;
}

#endif /* MG_DISABLE_RESOLVE */
