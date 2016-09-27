/*
 * Copyright (c) 2014 Cesanta Software Limited
 * All rights reserved
 */

/*
 * === URI
 */

#ifndef CS_MONGOOSE_SRC_URI_H_
#define CS_MONGOOSE_SRC_URI_H_

#include "mongoose/src/net.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Parses an URI and fills string chunks with locations of the respective
 * uri components within the input uri string. NULL pointers will be
 * ignored.
 *
 * General syntax:
 *
 *     [scheme://[user_info@]]host[:port][/path][?query][#fragment]
 *
 * Example:
 *
 *     foo.com:80
 *     tcp://foo.com:1234
 *     http://foo.com:80/bar?baz=1
 *     https://user:pw@foo.com:443/blah
 *
 * `path` will include the leading slash. `query` won't include the leading `?`.
 * `host` can contain embedded colons if surrounded by square brackets in order
 * to support IPv6 literal addresses.
 *
 *
 * Returns 0 on success, -1 on error.
 */
int mg_parse_uri(struct mg_str uri, struct mg_str *scheme,
                 struct mg_str *user_info, struct mg_str *host,
                 unsigned int *port, struct mg_str *path, struct mg_str *query,
                 struct mg_str *fragment);

int mg_normalize_uri_path(const struct mg_str *in, struct mg_str *out);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* CS_MONGOOSE_SRC_URI_H_ */
