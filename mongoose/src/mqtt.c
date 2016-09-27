/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

#ifndef MG_DISABLE_MQTT

#include <string.h>

#include "mongoose/src/internal.h"
#include "mongoose/src/mqtt.h"

MG_INTERNAL int parse_mqtt(struct mbuf *io, struct mg_mqtt_message *mm) {
  uint8_t header;
  int cmd;
  size_t len = 0;
  int var_len = 0;
  char *vlen = &io->buf[1];

  if (io->len < 2) return -1;

  header = io->buf[0];
  cmd = header >> 4;

  /* decode mqtt variable length */
  do {
    len += (*vlen & 127) << 7 * (vlen - &io->buf[1]);
  } while ((*vlen++ & 128) != 0 && ((size_t)(vlen - io->buf) <= io->len));

  if (len != 0 && io->len < (size_t)(len - 1)) return -1;

  mbuf_remove(io, 1 + (vlen - &io->buf[1]));
  mm->cmd = cmd;
  mm->qos = MG_MQTT_GET_QOS(header);

  switch (cmd) {
    case MG_MQTT_CMD_CONNECT:
      /* TODO(mkm): parse keepalive and will */
      break;
    case MG_MQTT_CMD_CONNACK:
      mm->connack_ret_code = io->buf[1];
      var_len = 2;
      break;
    case MG_MQTT_CMD_PUBACK:
    case MG_MQTT_CMD_PUBREC:
    case MG_MQTT_CMD_PUBREL:
    case MG_MQTT_CMD_PUBCOMP:
    case MG_MQTT_CMD_SUBACK:
      mm->message_id = ntohs(*(uint16_t *) io->buf);
      var_len = 2;
      break;
    case MG_MQTT_CMD_PUBLISH: {
      uint16_t topic_len = ntohs(*(uint16_t *) io->buf);
      mm->topic = (char *) MG_MALLOC(topic_len + 1);
      mm->topic[topic_len] = 0;
      strncpy(mm->topic, io->buf + 2, topic_len);
      var_len = topic_len + 2;

      if (MG_MQTT_GET_QOS(header) > 0) {
        mm->message_id = ntohs(*(uint16_t *) io->buf);
        var_len += 2;
      }
    } break;
    case MG_MQTT_CMD_SUBSCRIBE:
      /*
       * topic expressions are left in the payload and can be parsed with
       * `mg_mqtt_next_subscribe_topic`
       */
      mm->message_id = ntohs(*(uint16_t *) io->buf);
      var_len = 2;
      break;
    default:
      /* Unhandled command */
      break;
  }

  mbuf_remove(io, var_len);
  return len - var_len;
}

static void mqtt_handler(struct mg_connection *nc, int ev, void *ev_data) {
  int len;
  struct mbuf *io = &nc->recv_mbuf;
  struct mg_mqtt_message mm;
  memset(&mm, 0, sizeof(mm));

  nc->handler(nc, ev, ev_data);

  switch (ev) {
    case MG_EV_RECV:
      len = parse_mqtt(io, &mm);
      if (len == -1) break; /* not fully buffered */
      mm.payload.p = io->buf;
      mm.payload.len = len;

      nc->handler(nc, MG_MQTT_EVENT_BASE + mm.cmd, &mm);

      if (mm.topic) {
        MG_FREE(mm.topic);
      }
      mbuf_remove(io, mm.payload.len);
      break;
  }
}

void mg_set_protocol_mqtt(struct mg_connection *nc) {
  nc->proto_handler = mqtt_handler;
}

void mg_send_mqtt_handshake(struct mg_connection *nc, const char *client_id) {
  static struct mg_send_mqtt_handshake_opts opts;
  mg_send_mqtt_handshake_opt(nc, client_id, opts);
}

void mg_send_mqtt_handshake_opt(struct mg_connection *nc, const char *client_id,
                                struct mg_send_mqtt_handshake_opts opts) {
  uint8_t header = MG_MQTT_CMD_CONNECT << 4;
  uint8_t rem_len;
  uint16_t keep_alive;
  uint16_t len;

  /*
   * 9: version_header(len, magic_string, version_number), 1: flags, 2:
   * keep-alive timer,
   * 2: client_identifier_len, n: client_id
   */
  rem_len = 9 + 1 + 2 + 2 + (uint8_t) strlen(client_id);

  if (opts.user_name != NULL) {
    opts.flags |= MG_MQTT_HAS_USER_NAME;
    rem_len += (uint8_t) strlen(opts.user_name) + 2;
  }
  if (opts.password != NULL) {
    opts.flags |= MG_MQTT_HAS_PASSWORD;
    rem_len += (uint8_t) strlen(opts.password) + 2;
  }

  mg_send(nc, &header, 1);
  mg_send(nc, &rem_len, 1);
  mg_send(nc, "\00\06MQIsdp\03", 9);
  mg_send(nc, &opts.flags, 1);

  if (opts.keep_alive == 0) {
    opts.keep_alive = 60;
  }
  keep_alive = htons(opts.keep_alive);
  mg_send(nc, &keep_alive, 2);

  len = htons((uint16_t) strlen(client_id));
  mg_send(nc, &len, 2);
  mg_send(nc, client_id, strlen(client_id));

  if (opts.flags & MG_MQTT_HAS_USER_NAME) {
    len = htons((uint16_t) strlen(opts.user_name));
    mg_send(nc, &len, 2);
    mg_send(nc, opts.user_name, strlen(opts.user_name));
  }
  if (opts.flags & MG_MQTT_HAS_PASSWORD) {
    len = htons((uint16_t) strlen(opts.password));
    mg_send(nc, &len, 2);
    mg_send(nc, opts.password, strlen(opts.password));
  }
}

static void mg_mqtt_prepend_header(struct mg_connection *nc, uint8_t cmd,
                                   uint8_t flags, size_t len) {
  size_t off = nc->send_mbuf.len - len;
  uint8_t header = cmd << 4 | (uint8_t) flags;

  uint8_t buf[1 + sizeof(size_t)];
  uint8_t *vlen = &buf[1];

  assert(nc->send_mbuf.len >= len);

  buf[0] = header;

  /* mqtt variable length encoding */
  do {
    *vlen = len % 0x80;
    len /= 0x80;
    if (len > 0) *vlen |= 0x80;
    vlen++;
  } while (len > 0);

  mbuf_insert(&nc->send_mbuf, off, buf, vlen - buf);
}

void mg_mqtt_publish(struct mg_connection *nc, const char *topic,
                     uint16_t message_id, int flags, const void *data,
                     size_t len) {
  size_t old_len = nc->send_mbuf.len;

  uint16_t topic_len = htons((uint16_t) strlen(topic));
  uint16_t message_id_net = htons(message_id);

  mg_send(nc, &topic_len, 2);
  mg_send(nc, topic, strlen(topic));
  if (MG_MQTT_GET_QOS(flags) > 0) {
    mg_send(nc, &message_id_net, 2);
  }
  mg_send(nc, data, len);

  mg_mqtt_prepend_header(nc, MG_MQTT_CMD_PUBLISH, flags,
                         nc->send_mbuf.len - old_len);
}

void mg_mqtt_subscribe(struct mg_connection *nc,
                       const struct mg_mqtt_topic_expression *topics,
                       size_t topics_len, uint16_t message_id) {
  size_t old_len = nc->send_mbuf.len;

  uint16_t message_id_n = htons(message_id);
  size_t i;

  mg_send(nc, (char *) &message_id_n, 2);
  for (i = 0; i < topics_len; i++) {
    uint16_t topic_len_n = htons((uint16_t) strlen(topics[i].topic));
    mg_send(nc, &topic_len_n, 2);
    mg_send(nc, topics[i].topic, strlen(topics[i].topic));
    mg_send(nc, &topics[i].qos, 1);
  }

  mg_mqtt_prepend_header(nc, MG_MQTT_CMD_SUBSCRIBE, MG_MQTT_QOS(1),
                         nc->send_mbuf.len - old_len);
}

int mg_mqtt_next_subscribe_topic(struct mg_mqtt_message *msg,
                                 struct mg_str *topic, uint8_t *qos, int pos) {
  unsigned char *buf = (unsigned char *) msg->payload.p + pos;
  if ((size_t) pos >= msg->payload.len) {
    return -1;
  }

  topic->len = buf[0] << 8 | buf[1];
  topic->p = (char *) buf + 2;
  *qos = buf[2 + topic->len];
  return pos + 2 + topic->len + 1;
}

void mg_mqtt_unsubscribe(struct mg_connection *nc, char **topics,
                         size_t topics_len, uint16_t message_id) {
  size_t old_len = nc->send_mbuf.len;

  uint16_t message_id_n = htons(message_id);
  size_t i;

  mg_send(nc, (char *) &message_id_n, 2);
  for (i = 0; i < topics_len; i++) {
    uint16_t topic_len_n = htons((uint16_t) strlen(topics[i]));
    mg_send(nc, &topic_len_n, 2);
    mg_send(nc, topics[i], strlen(topics[i]));
  }

  mg_mqtt_prepend_header(nc, MG_MQTT_CMD_UNSUBSCRIBE, MG_MQTT_QOS(1),
                         nc->send_mbuf.len - old_len);
}

void mg_mqtt_connack(struct mg_connection *nc, uint8_t return_code) {
  uint8_t unused = 0;
  mg_send(nc, &unused, 1);
  mg_send(nc, &return_code, 1);
  mg_mqtt_prepend_header(nc, MG_MQTT_CMD_CONNACK, 0, 2);
}

/*
 * Sends a command which contains only a `message_id` and a QoS level of 1.
 *
 * Helper function.
 */
static void mg_send_mqtt_short_command(struct mg_connection *nc, uint8_t cmd,
                                       uint16_t message_id) {
  uint16_t message_id_net = htons(message_id);
  mg_send(nc, &message_id_net, 2);
  mg_mqtt_prepend_header(nc, cmd, MG_MQTT_QOS(1), 2);
}

void mg_mqtt_puback(struct mg_connection *nc, uint16_t message_id) {
  mg_send_mqtt_short_command(nc, MG_MQTT_CMD_PUBACK, message_id);
}

void mg_mqtt_pubrec(struct mg_connection *nc, uint16_t message_id) {
  mg_send_mqtt_short_command(nc, MG_MQTT_CMD_PUBREC, message_id);
}

void mg_mqtt_pubrel(struct mg_connection *nc, uint16_t message_id) {
  mg_send_mqtt_short_command(nc, MG_MQTT_CMD_PUBREL, message_id);
}

void mg_mqtt_pubcomp(struct mg_connection *nc, uint16_t message_id) {
  mg_send_mqtt_short_command(nc, MG_MQTT_CMD_PUBCOMP, message_id);
}

void mg_mqtt_suback(struct mg_connection *nc, uint8_t *qoss, size_t qoss_len,
                    uint16_t message_id) {
  size_t i;
  uint16_t message_id_net = htons(message_id);
  mg_send(nc, &message_id_net, 2);
  for (i = 0; i < qoss_len; i++) {
    mg_send(nc, &qoss[i], 1);
  }
  mg_mqtt_prepend_header(nc, MG_MQTT_CMD_SUBACK, MG_MQTT_QOS(1), 2 + qoss_len);
}

void mg_mqtt_unsuback(struct mg_connection *nc, uint16_t message_id) {
  mg_send_mqtt_short_command(nc, MG_MQTT_CMD_UNSUBACK, message_id);
}

void mg_mqtt_ping(struct mg_connection *nc) {
  mg_mqtt_prepend_header(nc, MG_MQTT_CMD_PINGREQ, 0, 0);
}

void mg_mqtt_pong(struct mg_connection *nc) {
  mg_mqtt_prepend_header(nc, MG_MQTT_CMD_PINGRESP, 0, 0);
}

void mg_mqtt_disconnect(struct mg_connection *nc) {
  mg_mqtt_prepend_header(nc, MG_MQTT_CMD_DISCONNECT, 0, 0);
}

#endif /* MG_DISABLE_MQTT */
