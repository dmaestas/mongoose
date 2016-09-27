/*
 * Copyright (c) 2004-2013 Sergey Lyubka
 * Copyright (c) 2013-2015 Cesanta Software Limited
 * All rights reserved
 *
 * This software is dual-licensed: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. For the terms of this
 * license, see <http://www.gnu.org/licenses/>.
 *
 * You are free to use this software under the terms of the GNU General
 * Public License, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * Alternatively, you can license this software under a commercial
 * license, as set out in <https://www.cesanta.com/license>.
 */

#ifndef CS_MONGOOSE_SRC_COMMON_H_
#define CS_MONGOOSE_SRC_COMMON_H_

#define MG_VERSION "6.5"

/* Local tweaks, applied before any of Mongoose's own headers. */
#ifdef MG_LOCALS
#include <mg_locals.h>
#endif

#if defined(MG_ENABLE_DEBUG) && !defined(CS_ENABLE_DEBUG)
#define CS_ENABLE_DEBUG
#endif
#if defined(MG_DISABLE_STDIO) && !defined(CS_DISABLE_STDIO)
#define CS_DISABLE_STDIO
#elif defined(CS_DISABLE_STDIO) && !defined(MG_DISABLE_STDIO)
#define MG_DISABLE_STDIO
#endif

/* All of the below features depend on filesystem access, disable them. */
#ifdef MG_DISABLE_FILESYSTEM
#ifndef MG_DISABLE_DAV
#define MG_DISABLE_DAV
#endif
#ifndef MG_DISABLE_CGI
#define MG_DISABLE_CGI
#endif
#ifndef MG_DISABLE_DIRECTORY_LISTING
#define MG_DISABLE_DIRECTORY_LISTING
#endif
#ifndef MG_DISABLE_DAV
#define MG_DISABLE_DAV
#endif
#endif /* MG_DISABLE_FILESYSTEM */

#ifdef MG_NO_BSD_SOCKETS
#ifndef MG_DISABLE_SYNC_RESOLVER
#define MG_DISABLE_SYNC_RESOLVER
#endif
#ifndef MG_DISABLE_SOCKETPAIR
#define MG_DISABLE_SOCKETPAIR
#endif
#endif /* MG_NO_BSD_SOCKETS */

#include "common/cs_dbg.h"

#endif /* CS_MONGOOSE_SRC_COMMON_H_ */
