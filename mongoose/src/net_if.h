/*
 * Copyright (c) 2014-2016 Cesanta Software Limited
 * All rights reserved
 */

#ifndef CS_MONGOOSE_SRC_NET_IF_H_
#define CS_MONGOOSE_SRC_NET_IF_H_

/*
 * Internal async networking core interface.
 * Consists of calls made by the core, which should not block,
 * and callbacks back into the core ("..._cb").
 * Callbacks may (will) cause methods to be invoked from within,
 * but methods are not allowed to invoke callbacks inline.
 *
 * Implementation must ensure that only one callback is invoked at any time.
 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Request that a TCP connection is made to the specified address. */
void mg_if_connect_tcp(struct mg_connection *nc,
                       const union socket_address *sa);
/* Open a UDP socket. Doesn't actually connect anything. */
void mg_if_connect_udp(struct mg_connection *nc);
/* Callback invoked by connect methods. err = 0 -> ok, != 0 -> error. */
void mg_if_connect_cb(struct mg_connection *nc, int err);

/* Set up a listening TCP socket on a given address. rv = 0 -> ok. */
int mg_if_listen_tcp(struct mg_connection *nc, union socket_address *sa);

/*
 * Deliver a new TCP connection. Returns NULL in case on error (unable to
 * create connection, in which case interface state should be discarded.
 * This is phase 1 of the two-phase process - MG_EV_ACCEPT will be delivered
 * when mg_if_accept_tcp_cb is invoked.
 */
struct mg_connection *mg_if_accept_new_conn(struct mg_connection *lc);
void mg_if_accept_tcp_cb(struct mg_connection *nc, union socket_address *sa,
                         size_t sa_len);

/* Request that a "listening" UDP socket be created. */
int mg_if_listen_udp(struct mg_connection *nc, union socket_address *sa);

/* Send functions for TCP and UDP. Sent data is copied before return. */
void mg_if_tcp_send(struct mg_connection *nc, const void *buf, size_t len);
void mg_if_udp_send(struct mg_connection *nc, const void *buf, size_t len);
/* Callback that reports that data has been put on the wire. */
void mg_if_sent_cb(struct mg_connection *nc, int num_sent);

/*
 * Receive callback.
 * buf must be heap-allocated and ownership is transferred to the core.
 * Core will acknowledge consumption by calling mg_if_recved.
 */
void mg_if_recv_tcp_cb(struct mg_connection *nc, void *buf, int len);
void mg_if_recv_udp_cb(struct mg_connection *nc, void *buf, int len,
                       union socket_address *sa, size_t sa_len);
void mg_if_recved(struct mg_connection *nc, size_t len);

/* Deliver a POLL event to the connection. */
void mg_if_poll(struct mg_connection *nc, time_t now);

/* Deliver a TIMER event to the connection. */
void mg_if_timer(struct mg_connection *c, double now);

/* Perform interface-related connection initialization. Return 1 on success. */
int mg_if_create_conn(struct mg_connection *nc);

/* Perform interface-related cleanup on connection before destruction. */
void mg_if_destroy_conn(struct mg_connection *nc);

void mg_close_conn(struct mg_connection *nc);

/* Put connection's address into *sa, local (remote = 0) or remote. */
void mg_if_get_conn_addr(struct mg_connection *nc, int remote,
                         union socket_address *sa);

/* Associate a socket to a connection. */
void mg_sock_set(struct mg_connection *nc, sock_t sock);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CS_MONGOOSE_SRC_NET_IF_H_ */
