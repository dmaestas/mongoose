/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#include "mongoose/src/internal.h"
#include "mongoose/src/mqtt-broker.h"

#ifdef MG_ENABLE_MQTT_BROKER

static void mg_mqtt_session_init(struct mg_mqtt_broker *brk,
                                 struct mg_mqtt_session *s,
                                 struct mg_connection *nc) {
  s->brk = brk;
  s->subscriptions = NULL;
  s->num_subscriptions = 0;
  s->nc = nc;
}

static void mg_mqtt_add_session(struct mg_mqtt_session *s) {
  s->next = s->brk->sessions;
  s->brk->sessions = s;
  s->prev = NULL;
  if (s->next != NULL) s->next->prev = s;
}

static void mg_mqtt_remove_session(struct mg_mqtt_session *s) {
  if (s->prev == NULL) s->brk->sessions = s->next;
  if (s->prev) s->prev->next = s->next;
  if (s->next) s->next->prev = s->prev;
}

static void mg_mqtt_destroy_session(struct mg_mqtt_session *s) {
  size_t i;
  for (i = 0; i < s->num_subscriptions; i++) {
    MG_FREE((void *) s->subscriptions[i].topic);
  }
  MG_FREE(s->subscriptions);
  MG_FREE(s);
}

static void mg_mqtt_close_session(struct mg_mqtt_session *s) {
  mg_mqtt_remove_session(s);
  mg_mqtt_destroy_session(s);
}

void mg_mqtt_broker_init(struct mg_mqtt_broker *brk, void *user_data) {
  brk->sessions = NULL;
  brk->user_data = user_data;
}

static void mg_mqtt_broker_handle_connect(struct mg_mqtt_broker *brk,
                                          struct mg_connection *nc) {
  struct mg_mqtt_session *s = (struct mg_mqtt_session *) malloc(sizeof *s);
  if (s == NULL) {
    /* LCOV_EXCL_START */
    mg_mqtt_connack(nc, MG_EV_MQTT_CONNACK_SERVER_UNAVAILABLE);
    return;
    /* LCOV_EXCL_STOP */
  }

  /* TODO(mkm): check header (magic and version) */

  mg_mqtt_session_init(brk, s, nc);
  s->user_data = nc->user_data;
  nc->user_data = s;
  mg_mqtt_add_session(s);

  mg_mqtt_connack(nc, MG_EV_MQTT_CONNACK_ACCEPTED);
}

static void mg_mqtt_broker_handle_subscribe(struct mg_connection *nc,
                                            struct mg_mqtt_message *msg) {
  struct mg_mqtt_session *ss = (struct mg_mqtt_session *) nc->user_data;
  uint8_t qoss[512];
  size_t qoss_len = 0;
  struct mg_str topic;
  uint8_t qos;
  int pos;
  struct mg_mqtt_topic_expression *te;

  for (pos = 0;
       (pos = mg_mqtt_next_subscribe_topic(msg, &topic, &qos, pos)) != -1;) {
    qoss[qoss_len++] = qos;
  }

  ss->subscriptions = (struct mg_mqtt_topic_expression *) realloc(
      ss->subscriptions, sizeof(*ss->subscriptions) * qoss_len);
  for (pos = 0;
       (pos = mg_mqtt_next_subscribe_topic(msg, &topic, &qos, pos)) != -1;
       ss->num_subscriptions++) {
    te = &ss->subscriptions[ss->num_subscriptions];
    te->topic = (char *) malloc(topic.len + 1);
    te->qos = qos;
    strncpy((char *) te->topic, topic.p, topic.len + 1);
  }

  mg_mqtt_suback(nc, qoss, qoss_len, msg->message_id);
}

/*
 * Matches a topic against a topic expression
 *
 * See http://goo.gl/iWk21X
 *
 * Returns 1 if it matches; 0 otherwise.
 */
static int mg_mqtt_match_topic_expression(const char *exp, const char *topic) {
  /* TODO(mkm): implement real matching */
  int len = strlen(exp);
  if (strchr(exp, '#')) {
    len -= 2;
  }
  return strncmp(exp, topic, len) == 0;
}

static void mg_mqtt_broker_handle_publish(struct mg_mqtt_broker *brk,
                                          struct mg_mqtt_message *msg) {
  struct mg_mqtt_session *s;
  size_t i;

  for (s = mg_mqtt_next(brk, NULL); s != NULL; s = mg_mqtt_next(brk, s)) {
    for (i = 0; i < s->num_subscriptions; i++) {
      if (mg_mqtt_match_topic_expression(s->subscriptions[i].topic,
                                         msg->topic)) {
        mg_mqtt_publish(s->nc, msg->topic, 0, 0, msg->payload.p,
                        msg->payload.len);
        break;
      }
    }
  }
}

void mg_mqtt_broker(struct mg_connection *nc, int ev, void *data) {
  struct mg_mqtt_message *msg = (struct mg_mqtt_message *) data;
  struct mg_mqtt_broker *brk;

  if (nc->listener) {
    brk = (struct mg_mqtt_broker *) nc->listener->user_data;
  } else {
    brk = (struct mg_mqtt_broker *) nc->user_data;
  }

  switch (ev) {
    case MG_EV_ACCEPT:
      mg_set_protocol_mqtt(nc);
      break;
    case MG_EV_MQTT_CONNECT:
      mg_mqtt_broker_handle_connect(brk, nc);
      break;
    case MG_EV_MQTT_SUBSCRIBE:
      mg_mqtt_broker_handle_subscribe(nc, msg);
      break;
    case MG_EV_MQTT_PUBLISH:
      mg_mqtt_broker_handle_publish(brk, msg);
      break;
    case MG_EV_CLOSE:
      if (nc->listener) {
        mg_mqtt_close_session((struct mg_mqtt_session *) nc->user_data);
      }
      break;
  }
}

struct mg_mqtt_session *mg_mqtt_next(struct mg_mqtt_broker *brk,
                                     struct mg_mqtt_session *s) {
  return s == NULL ? brk->sessions : s->next;
}

#endif /* MG_ENABLE_MQTT_BROKER */
