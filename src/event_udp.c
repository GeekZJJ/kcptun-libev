/* kcptun-libev (c) 2019-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "event.h"
#include "conf.h"
#include "pktqueue.h"
#include "server.h"
#include "session.h"
#include "sockutil.h"
#include "util.h"

#include "algo/hashtable.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <unistd.h>

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

void udp_session_timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);

	struct session *restrict ss = watcher->data;
	struct server *restrict s = ss->server;

	if (LOGLEVEL(INFO)) {
		LOG_F(INFO, "udp session [%08" PRIX32 "] timeout", ss->conv);
	}

	s->sessions = table_del(s->sessions, SESSION_GETKEY(ss), NULL);
	s->sessions_udp = table_del(s->sessions_udp, SESSION_UDP_GETKEY(ss), NULL);
	ev_timer_stop(loop, watcher);
	session_free(ss);
}

static struct session* accept_one_udp(
	struct server *restrict s, const struct sockaddr *client_sa)
{
	/* Initialize and start watcher to read client requests */
	struct session *restrict ss;
	uint32_t conv = conv_new_udp(s, &s->pkt.kcp_connect.sa);
	ss = session_new_udp(s, &s->pkt.kcp_connect, conv);
	if (ss == NULL) {
		LOGOOM();
		return NULL;
	}
	SESSION_UDP_MAKEKEY(ss->udpkey, client_sa);
	ss->kcp_state = STATE_CONNECT;
	ss->tcp_state = STATE_CONNECTED;
	void *elem = ss;
	s->sessions = table_set(s->sessions, SESSION_GETKEY(ss), &elem);
	assert(elem == NULL);
	elem = ss;
	s->sessions_udp = table_set(s->sessions_udp, SESSION_UDP_GETKEY(ss), &elem);
	assert(elem == NULL);
	ss->craddr.sa = *client_sa;
	if (LOGLEVEL(INFO)) {
		char addr_str[64];
		format_sa(client_sa, addr_str, sizeof(addr_str));
		LOG_F(INFO, "session [%08" PRIX32 "] udp: accepted %s", conv, addr_str);
	}
	return ss;
}

void client_udp_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_READ);

	struct server *restrict s = watcher->data;

	for (;;) {
		unsigned char buf[65535] = {0};
		union sockaddr_max addr;
		socklen_t addrlen = sizeof(addr);
		const ssize_t nbrecv = recvfrom(watcher->fd, buf, sizeof(buf), 0, &addr.sa, &addrlen);
		if (nbrecv < 0) {
			const int err = errno;
			if (IS_TRANSIENT_ERROR(err)) {
				break;
			}
			LOGE_F("udp client recvfrom failed: %s", strerror(err));
			break;
		}

		if (!s->pkt.connected) {
			LOGE("packet connection is not ready, refusing");
			return;
		}

		unsigned char sskey[SESSION_UDP_KEY_SIZE];
		SESSION_UDP_MAKEKEY(sskey, &addr.sa);
		const struct hashkey hkey = {
			.len = sizeof(sskey),
			.data = sskey,
		};
		struct session *restrict ss;
		if (table_find(s->sessions_udp, hkey, (void **)&ss)) {
			assert(ss->is_udp);
			if (!kcp_cansend(ss)) {
				LOG_RATELIMITED_F(
					ERROR, ev_now(loop), 1.0,
					"session [%08" PRIX32 "] kcp can't send, drop 1 pkt (len = %d)", ss->conv, nbrecv);
				continue;
			}
			kcp_send(ss, buf, nbrecv);
			ev_timer_again(loop, & ss->w_udp_timeout);
			LOGV_F("session [%08" PRIX32 "] udp timer reset", ss->conv);
			continue;
		}

		if (table_size(s->sessions) >= MAX_SESSIONS) {
			LOG_RATELIMITED(
				ERROR, ev_now(loop), 1.0,
				"* max session count exceeded, new connections refused");
			continue;
		}

		ss = accept_one_udp(s, &addr.sa);
		kcp_send(ss, buf, nbrecv);
	}
}

void server_udp_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	UNUSED(loop);
	CHECK_REVENTS(revents, EV_READ);

	struct session *restrict ss = watcher->data;

	for (;;) {
		uint8_t buf[65535] = {0};
		union sockaddr_max addr;
		socklen_t addrlen = sizeof(addr);
		/* Receive message from client socket */
		const ssize_t nread = recvfrom(watcher->fd, buf, sizeof(buf), 0, &addr.sa, &addrlen);
		if (nread < 0) {
			const int err = errno;
			if (IS_TRANSIENT_ERROR(err)) {
				break;
			}
			LOGE_F("session [%08" PRIX32 "] udp recv: %s", ss->conv, strerror(err));
			break;
		}
		if (!kcp_cansend(ss)) {
			LOG_RATELIMITED_F(
				ERROR, ev_now(loop), 1.0,
				"session [%08" PRIX32 "] kcp can't send, drop 1 pkt (len = %d)", ss->conv, nread);
			break;
		}
		kcp_send(ss, buf, nread);
	}
}
