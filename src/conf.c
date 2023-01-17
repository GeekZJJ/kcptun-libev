/* kcptun-libev (c) 2019-2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "conf.h"
#include "utils/arraysize.h"
#include "utils/slog.h"
#include "net/addr.h"
#include "util.h"
#include "sockutil.h"
#include "jsonutil.h"

#include <sys/socket.h>

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define MAX_CONF_SIZE 65536

static json_value *conf_parse(const char *filename)
{
	FILE *f = fopen(filename, "r");
	if (f == NULL) {
		const int err = errno;
		LOGE_F("unable to open config file: %s", strerror(err));
		return NULL;
	}
	if (fseek(f, 0, SEEK_END)) {
		const int err = errno;
		LOGE_F("unable to seek config file: %s", strerror(err));
		fclose(f);
		return NULL;
	}
	const long len = ftell(f);
	if (len < 0) {
		const int err = errno;
		LOGE_F("unable to tell config file length: %s", strerror(err));
		fclose(f);
		return NULL;
	}
	if (len >= MAX_CONF_SIZE) {
		LOGE("config file is too large");
		fclose(f);
		return NULL;
	}
	if (fseek(f, 0, SEEK_SET)) {
		const int err = errno;
		LOGE_F("unable to seek config file: %s", strerror(err));
		fclose(f);
		return NULL;
	}
	char *buf = malloc(len + 1); /* null terminator */
	if (buf == NULL) {
		LOGF("conf_parse: out of memory");
		fclose(f);
		return NULL;
	}
	const size_t nread = fread(buf, sizeof(char), (size_t)len, f);
	fclose(f);
	if (nread != (size_t)len) {
		LOGE("unable to read the config file");
		free(buf);
		return NULL;
	}
	buf[nread] = '\0';
	json_value *obj = parse_json(buf, nread);
	free(buf);
	if (obj == NULL) {
		LOGF("conf_parse: json parse failed");
		return NULL;
	}
	return obj;
}

static bool kcp_scope_cb(void *ud, const json_object_entry *entry)
{
	struct config *restrict conf = ud;
	const char *name = entry->name;
	const json_value *value = entry->value;
	if (strcmp(name, "mtu") == 0) {
		return parse_int_json(&conf->kcp_mtu, value);
	}
	if (strcmp(name, "sndwnd") == 0) {
		return parse_int_json(&conf->kcp_sndwnd, value);
	}
	if (strcmp(name, "rcvwnd") == 0) {
		return parse_int_json(&conf->kcp_rcvwnd, value);
	}
	if (strcmp(name, "nodelay") == 0) {
		return parse_int_json(&conf->kcp_nodelay, value);
	}
	if (strcmp(name, "interval") == 0) {
		return parse_int_json(&conf->kcp_interval, value);
	}
	if (strcmp(name, "resend") == 0) {
		return parse_int_json(&conf->kcp_resend, value);
	}
	if (strcmp(name, "nc") == 0) {
		return parse_int_json(&conf->kcp_nc, value);
	}
	if (strcmp(name, "flush") == 0) {
		return parse_int_json(&conf->kcp_flush, value);
	}
	LOGW_F("unknown config: \"kcp.%s\"", name);
	return true;
}

static bool tcp_scope_cb(void *ud, const json_object_entry *entry)
{
	struct config *restrict conf = ud;
	const char *name = entry->name;
	const json_value *value = entry->value;
	if (strcmp(name, "reuseport") == 0) {
		return parse_bool_json(&conf->tcp_reuseport, value);
	}
	if (strcmp(name, "keepalive") == 0) {
		return parse_bool_json(&conf->tcp_keepalive, value);
	}
	if (strcmp(name, "nodelay") == 0) {
		return parse_bool_json(&conf->tcp_nodelay, value);
	}
	if (strcmp(name, "sndbuf") == 0) {
		return parse_int_json(&conf->tcp_sndbuf, value);
	}
	if (strcmp(name, "rcvbuf") == 0) {
		return parse_int_json(&conf->tcp_rcvbuf, value);
	}
	LOGW_F("unknown config: \"tcp.%s\"", name);
	return true;
}

static bool udp_scope_cb(void *ud, const json_object_entry *entry)
{
	struct config *restrict conf = ud;
	const char *name = entry->name;
	const json_value *value = entry->value;
	if (strcmp(name, "sndbuf") == 0) {
		return parse_int_json(&conf->udp_sndbuf, value);
	}
	if (strcmp(name, "rcvbuf") == 0) {
		return parse_int_json(&conf->udp_rcvbuf, value);
	}
	LOGW_F("unknown config: \"udp.%s\"", name);
	return true;
}

static bool main_scope_cb(void *ud, const json_object_entry *entry)
{
	struct config *restrict conf = ud;
	const char *name = entry->name;
	const json_value *value = entry->value;
	if (strcmp(name, "kcp") == 0) {
		return walk_json_object(conf, value, kcp_scope_cb);
	}
	if (strcmp(name, "udp") == 0) {
		return walk_json_object(conf, value, udp_scope_cb);
	}
	if (strcmp(name, "tcp") == 0) {
		return walk_json_object(conf, value, tcp_scope_cb);
	}
	if (strcmp(name, "listen") == 0) {
		conf->listen.str = parse_string_json(value);
		return conf->listen.str != NULL;
	}
	if (strcmp(name, "connect") == 0) {
		conf->connect.str = parse_string_json(value);
		return conf->connect.str != NULL;
	}
	if (strcmp(name, "kcp_bind") == 0) {
		conf->kcp_bind.str = parse_string_json(value);
		return conf->kcp_bind.str != NULL;
	}
	if (strcmp(name, "kcp_connect") == 0) {
		conf->kcp_connect.str = parse_string_json(value);
		return conf->kcp_connect.str != NULL;
	}
	if (strcmp(name, "http_listen") == 0) {
		conf->http_listen.str = parse_string_json(value);
		return conf->http_listen.str != NULL;
	}
	if (strcmp(name, "netdev") == 0) {
		conf->netdev = parse_string_json(value);
		return conf->netdev != NULL;
	}
#if WITH_CRYPTO
	if (strcmp(name, "method") == 0) {
		conf->method = parse_string_json(value);
		return conf->method != NULL;
	}
	if (strcmp(name, "password") == 0) {
		conf->password = parse_string_json(value);
		return conf->password != NULL;
	}
	if (strcmp(name, "psk") == 0) {
		conf->psk = parse_b64_json(value, &conf->psklen);
		return conf->psk != NULL;
	}
#endif /* WITH_CRYPTO */
#if WITH_OBFS
	if (strcmp(name, "obfs") == 0) {
		conf->obfs = parse_string_json(value);
		return conf->obfs != NULL;
	}
#endif /* WITH_OBFS */
	if (strcmp(name, "linger") == 0) {
		return parse_int_json(&conf->linger, value);
	}
	if (strcmp(name, "timeout") == 0) {
		return parse_int_json(&conf->timeout, value);
	}
	if (strcmp(name, "keepalive") == 0) {
		return parse_int_json(&conf->keepalive, value);
	}
	if (strcmp(name, "time_wait") == 0) {
		return parse_int_json(&conf->time_wait, value);
	}
	if (strcmp(name, "loglevel") == 0) {
		return parse_int_json(&conf->log_level, value);
	}
	if (strcmp(name, "user") == 0) {
		conf->user = parse_string_json(value);
		return conf->user != NULL;
	}
	LOGW_F("unknown config: \"%s\"", name);
	return true;
}

const char *runmode_str(const int mode)
{
	static const char *str[] = {
		[MODE_SERVER] = "server",
		[MODE_CLIENT] = "client",
	};
	assert(mode >= 0);
	assert((size_t)mode < ARRAY_SIZE(str));
	return str[mode];
}

bool resolve_netaddr(struct netaddr *restrict addr, int flags)
{
	char *hostname = NULL;
	char *service = NULL;
	char *str = strdup(addr->str);
	if (str == NULL) {
		return NULL;
	}
	if (!splithostport(str, &hostname, &service)) {
		LOGE_F("failed splitting address: \"%s\"", addr->str);
		free(str);
		return false;
	}
	if (hostname[0] == '\0') {
		hostname = "0.0.0.0";
	}
	struct sockaddr *sa = resolve_sa(hostname, service, flags);
	if (sa == NULL) {
		LOGE_F("failed resolving address: \"%s\"", addr->str);
		free(str);
		return false;
	}
	UTIL_SAFE_FREE(addr->sa);
	addr->sa = sa;
	if (LOGLEVEL(LOG_LEVEL_DEBUG)) {
		char addr_str[64];
		format_sa(sa, addr_str, sizeof(addr_str));
		LOGD_F("resolve: \"%s\" is %s", addr->str, addr_str);
	}
	free(str);
	return true;
}

static struct config conf_default(void)
{
	return (struct config){
		.kcp_mtu = 1400,
		.kcp_sndwnd = 256,
		.kcp_rcvwnd = 256,
		.kcp_nodelay = 1,
		.kcp_interval = 50,
		.kcp_resend = 0,
		.kcp_nc = 1,
		.kcp_flush = 1,
		.timeout = 600,
		.linger = 30,
		.keepalive = 25,
		.time_wait = 120,
		.tcp_reuseport = false,
		.tcp_keepalive = false,
		.tcp_nodelay = true,
		.log_level = LOG_LEVEL_INFO,
	};
}

static bool
conf_check_range(const char *key, const int value, const int min, const int max)
{
	if (value < min || value > max) {
		LOGE_F("config: %s is out of range (%d - %d)", key, min, max);
		return false;
	}
	return true;
}

static bool conf_check(struct config *restrict conf)
{
	/* 1. network address check */
	int mode = 0;
	if (conf->kcp_bind.str != NULL && conf->connect.str != NULL) {
		mode |= MODE_SERVER;
	}
	if (conf->listen.str != NULL && conf->kcp_connect.str != NULL) {
		mode |= MODE_CLIENT;
	}
	if (mode != MODE_SERVER && mode != MODE_CLIENT) {
		LOGE("config: no forward could be provided (are you missing some address field?)");
		return false;
	}
	conf->mode = mode;

#if WITH_CRYPTO
	/* 2. crypto check */
	if (conf->psk != NULL && conf->password != NULL) {
		LOGF("config: psk and password cannot be specified at the same time");
		return false;
	}
#endif

	/* 3. range check */
	const bool range_ok =
		conf_check_range("kcp.mtu", conf->kcp_mtu, 300, 1400) &&
		conf_check_range("kcp.sndwnd", conf->kcp_sndwnd, 16, 65536) &&
		conf_check_range("kcp.rcvwnd", conf->kcp_rcvwnd, 16, 65536) &&
		conf_check_range("kcp.nodelay", conf->kcp_nodelay, 0, 2) &&
		conf_check_range("kcp.interval", conf->kcp_interval, 10, 500) &&
		conf_check_range("kcp.resend", conf->kcp_resend, 0, 100) &&
		conf_check_range("kcp.nc", conf->kcp_nc, 0, 1) &&
		conf_check_range("kcp.flush", conf->kcp_flush, 0, 2) &&
		conf_check_range("timeout", conf->timeout, 60, 86400) &&
		conf_check_range("linger", conf->linger, 5, 600) &&
		conf_check_range("keepalive", conf->keepalive, 0, 600) &&
		conf_check_range("time_wait", conf->time_wait, 5, 3600) &&
		conf_check_range("log_level", conf->log_level, 0, 6);
	if (!range_ok) {
		return false;
	}

	return true;
}

struct config *conf_read(const char *filename)
{
	struct config *conf = malloc(sizeof(struct config));
	if (conf == NULL) {
		return NULL;
	}
	*conf = conf_default();
	json_value *obj = conf_parse(filename);
	if (obj == NULL) {
		conf_free(conf);
		return NULL;
	}
	if (!walk_json_object(conf, obj, main_scope_cb)) {
		LOGE("invalid config file");
		conf_free(conf);
		json_value_free(obj);
		return NULL;
	}
	json_value_free(obj);
	if (!conf_check(conf)) {
		conf_free(conf);
		return NULL;
	}
	return conf;
}

static void netaddr_safe_free(struct netaddr *restrict addr)
{
	UTIL_SAFE_FREE(addr->str);
	UTIL_SAFE_FREE(addr->sa);
}

void conf_free(struct config *conf)
{
	netaddr_safe_free(&conf->listen);
	netaddr_safe_free(&conf->connect);
	netaddr_safe_free(&conf->kcp_bind);
	netaddr_safe_free(&conf->kcp_connect);
	netaddr_safe_free(&conf->http_listen);
	UTIL_SAFE_FREE(conf->netdev);
	UTIL_SAFE_FREE(conf->user);
#if WITH_CRYPTO
	UTIL_SAFE_FREE(conf->method);
	UTIL_SAFE_FREE(conf->password);
	UTIL_SAFE_FREE(conf->psk);
#endif
#if WITH_OBFS
	UTIL_SAFE_FREE(conf->obfs);
#endif
	free(conf);
}
