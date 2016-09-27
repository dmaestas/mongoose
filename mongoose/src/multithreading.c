/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#include "mongoose/src/internal.h"
#include "mongoose/src/util.h"

#ifdef MG_ENABLE_THREADS

static void multithreaded_ev_handler(struct mg_connection *c, int ev, void *p);

/*
 * This thread function executes user event handler.
 * It runs an event manager that has only one connection, until that
 * connection is alive.
 */
static void *per_connection_thread_function(void *param) {
  struct mg_connection *c = (struct mg_connection *) param;
  struct mg_mgr m;
  /* mgr_data can be used subsequently, store its value */
  int poll_timeout = (intptr_t) c->mgr_data;

  mg_mgr_init(&m, NULL);
  mg_add_conn(&m, c);
  mg_call(c, NULL, MG_EV_ACCEPT, &c->sa);

  while (m.active_connections != NULL) {
    mg_mgr_poll(&m, poll_timeout ? poll_timeout : 1000);
  }
  mg_mgr_free(&m);

  return param;
}

static void link_conns(struct mg_connection *c1, struct mg_connection *c2) {
  c1->priv_2 = c2;
  c2->priv_2 = c1;
}

static void unlink_conns(struct mg_connection *c) {
  struct mg_connection *peer = (struct mg_connection *) c->priv_2;
  if (peer != NULL) {
    peer->flags |= MG_F_SEND_AND_CLOSE;
    peer->priv_2 = NULL;
  }
  c->priv_2 = NULL;
}

static void forwarder_ev_handler(struct mg_connection *c, int ev, void *p) {
  (void) p;
  if (ev == MG_EV_RECV && c->priv_2) {
    mg_forward(c, (struct mg_connection *) c->priv_2);
  } else if (ev == MG_EV_CLOSE) {
    unlink_conns(c);
  }
}

static void spawn_handling_thread(struct mg_connection *nc) {
  struct mg_mgr dummy;
  sock_t sp[2];
  struct mg_connection *c[2];
  int poll_timeout;
  /*
   * Create a socket pair, and wrap each socket into the connection with
   * dummy event manager.
   * c[0] stays in this thread, c[1] goes to another thread.
   */
  mg_socketpair(sp, SOCK_STREAM);
  memset(&dummy, 0, sizeof(dummy));
  c[0] = mg_add_sock(&dummy, sp[0], forwarder_ev_handler);
  c[1] = mg_add_sock(&dummy, sp[1], nc->listener->priv_1.f);

  /* link_conns replaces priv_2, storing its value */
  poll_timeout = (intptr_t) nc->priv_2;

  /* Interlink client connection with c[0] */
  link_conns(c[0], nc);

  /*
   * Switch c[0] manager from the dummy one to the real one. c[1] manager
   * will be set in another thread, allocated on stack of that thread.
   */
  mg_add_conn(nc->mgr, c[0]);

  /*
   * Dress c[1] as nc.
   * TODO(lsm): code in accept_conn() looks similar. Refactor.
   */
  c[1]->listener = nc->listener;
  c[1]->proto_handler = nc->proto_handler;
  c[1]->user_data = nc->user_data;
  c[1]->sa = nc->sa;
  c[1]->flags = nc->flags;

  /* priv_2 is used, so, put timeout to mgr_data */
  c[1]->mgr_data = (void *) (intptr_t) poll_timeout;

  mg_start_thread(per_connection_thread_function, c[1]);
}

static void multithreaded_ev_handler(struct mg_connection *c, int ev, void *p) {
  (void) p;
  if (ev == MG_EV_ACCEPT) {
    spawn_handling_thread(c);
    c->handler = forwarder_ev_handler;
  }
}

void mg_enable_multithreading_opt(struct mg_connection *nc,
                                  struct mg_multithreading_opts opts) {
  /* Wrap user event handler into our multithreaded_ev_handler */
  nc->priv_1.f = nc->handler;
  /*
   * We put timeout to `priv_2` member of the main
   * (listening) connection, mt is not enabled yet,
   * and this member is not used
   */
  nc->priv_2 = (void *) (intptr_t) opts.poll_timeout;
  nc->handler = multithreaded_ev_handler;
}

void mg_enable_multithreading(struct mg_connection *nc) {
  struct mg_multithreading_opts opts;
  memset(&opts, 0, sizeof(opts));
  mg_enable_multithreading_opt(nc, opts);
}

#endif
