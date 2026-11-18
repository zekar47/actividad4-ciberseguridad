/*
 * a4-api: endpoint HTTP mínimo con OAuth 2.0 (client credentials), JWT HS256,
 * validación estricta de entradas y rate limiting.
 *
 * Este servidor es didáctico. No sustituye a un framework de producción:
 * no implementa TLS (debe ir detrás de un proxy), ni persistencia,
 * ni revocación distribuida de tokens.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "config.h"

/* ------------------------------------------------------------------------- */
/* Configuración efectiva                                                    */
/* ------------------------------------------------------------------------- */

static const char *g_jwt_secret = JWT_SECRET_DEFAULT;
static const char *g_client_secret = CLIENT_SECRET_DEFAULT;
static int g_rate_limit = RATE_LIMIT;
static int g_rate_window = RATE_WINDOW;

/* ------------------------------------------------------------------------- */
/* HMAC-SHA-256 (OpenSSL libcrypto)                                          */
/* ------------------------------------------------------------------------- */

/*
 * Se delega la primitiva criptográfica a OpenSSL en lugar de mantener una
 * implementación propia. El resto del servidor sigue siendo libc/POSIX; esta
 * es la única dependencia externa y evita errores sutiles en criptografía.
 */
static int hmac_sha256(const unsigned char *key, size_t keylen,
		       const unsigned char *msg, size_t msglen,
		       unsigned char out[32])
{
	size_t outlen = 0;

	if (EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL,
		      key, keylen, msg, msglen, out, 32, &outlen) == NULL)
		return -1;
	return outlen == 32 ? 0 : -1;
}

/* Comparación en tiempo constante (para secretos y firmas). */
static int ct_equal(const void *a, const void *b, size_t n)
{
	const unsigned char *x = a;
	const unsigned char *y = b;
	unsigned char r = 0;
	size_t i;

	for (i = 0; i < n; i++)
		r |= (unsigned char)(x[i] ^ y[i]);
	return r == 0;
}

static int ct_streq(const char *a, const char *b)
{
	size_t la = strlen(a);
	size_t lb = strlen(b);

	if (la != lb)
		return 0;
	return ct_equal(a, b, la);
}

/* ------------------------------------------------------------------------- */
/* Base64url (JWT)                                                           */
/* ------------------------------------------------------------------------- */

static const char b64url_tab[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static int b64url_value(unsigned char c)
{
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '-') return 62;
	if (c == '_') return 63;
	return -1;
}

static size_t b64url_encode(const unsigned char *in, size_t len,
			    char *out, size_t cap)
{
	size_t i, o = 0;

	for (i = 0; i < len; i += 3) {
		uint32_t v = (uint32_t)in[i] << 16;
		if (i + 1 < len)
			v |= (uint32_t)in[i + 1] << 8;
		if (i + 2 < len)
			v |= in[i + 2];
		if (o + 4 >= cap)
			return 0;
		out[o++] = b64url_tab[(v >> 18) & 0x3f];
		out[o++] = b64url_tab[(v >> 12) & 0x3f];
		if (i + 1 < len)
			out[o++] = b64url_tab[(v >> 6) & 0x3f];
		if (i + 2 < len)
			out[o++] = b64url_tab[v & 0x3f];
	}
	out[o] = '\0';
	return o;
}

static int b64url_decode(const char *in, size_t len,
			 unsigned char *out, size_t cap, size_t *outlen)
{
	uint32_t acc = 0;
	int bits = 0;
	size_t i, o = 0;

	while (len > 0 && in[len - 1] == '=')
		len--;
	if (len % 4 == 1)
		return -1;

	for (i = 0; i < len; i++) {
		int v;
		if (in[i] == '=')
			return -1;
		v = b64url_value((unsigned char)in[i]);
		if (v < 0)
			return -1;
		acc = (acc << 6) | (uint32_t)v;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			if (o >= cap)
				return -1;
			out[o++] = (unsigned char)((acc >> bits) & 0xff);
		}
	}
	*outlen = o;
	return 0;
}

/* ------------------------------------------------------------------------- */
/* Parser JSON plano y estricto                                              */
/*                                                                          */
/* Solo acepta objetos con valores string o entero. Rechaza duplicados,      */
/* controles, UTF-8 no ASCII, floats, booleanos y null. Es intencional: el   */
/* contrato de la API es pequeño y cerrado.                                  */
/* ------------------------------------------------------------------------- */

#define JF_MAX 16
#define JF_KEY 32
#define JF_VAL 256

enum { JF_STR = 1, JF_INT = 2 };

struct jfield {
	char key[JF_KEY];
	int type;
	char s[JF_VAL];
	long n;
};

static void skip_ws(const char **pp, const char *end)
{
	while (*pp < end && (**pp == ' ' || **pp == '\t' ||
			    **pp == '\r' || **pp == '\n'))
		(*pp)++;
}

static int hexval(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static int json_string(const char **pp, const char *end, char *out, size_t cap)
{
	const char *p = *pp;
	size_t o = 0;

	if (p >= end || *p != '"')
		return -1;
	p++;
	while (p < end && *p != '"') {
		unsigned char c = (unsigned char)*p++;

		if (c < 0x20)
			return -1;
		if (c == '\\') {
			if (p >= end)
				return -1;
			switch (*p++) {
			case '"': c = '"'; break;
			case '\\': c = '\\'; break;
			case '/': c = '/'; break;
			case 'b': c = '\b'; break;
			case 'f': c = '\f'; break;
			case 'n': c = '\n'; break;
			case 'r': c = '\r'; break;
			case 't': c = '\t'; break;
			case 'u': {
				unsigned v = 0;
				int i;
				if (end - p < 4)
					return -1;
				for (i = 0; i < 4; i++) {
					int h = hexval((unsigned char)p[i]);
					if (h < 0)
						return -1;
					v = (v << 4) | (unsigned)h;
				}
				p += 4;
				/* Contrato ASCII: sin NUL ni caracteres de control. */
				if (v == 0 || v > 0x7e)
					return -1;
				c = (unsigned char)v;
				break;
			}
			default:
				return -1;
			}
		} else if (c >= 0x7f) {
			return -1;
		}
		if (o + 1 >= cap)
			return -1;
		out[o++] = (char)c;
	}
	if (p >= end || *p != '"')
		return -1;
	p++;
	out[o] = '\0';
	*pp = p;
	return 0;
}

static int json_integer(const char **pp, const char *end, long *out)
{
	const char *p = *pp;
	int neg = 0;
	unsigned long v = 0;

	if (p < end && *p == '-') {
		neg = 1;
		p++;
	}
	if (p >= end || !isdigit((unsigned char)*p))
		return -1;
	if (*p == '0' && p + 1 < end && isdigit((unsigned char)p[1]))
		return -1;
	while (p < end && isdigit((unsigned char)*p)) {
		unsigned d = (unsigned)(*p - '0');
		if (v > (unsigned long)LONG_MAX / 10)
			return -1;
		v = v * 10 + d;
		if (v > (unsigned long)LONG_MAX)
			return -1;
		p++;
	}
	*out = neg ? -(long)v : (long)v;
	*pp = p;
	return 0;
}

static int json_parse_object(const char *s, size_t len, struct jfield *f,
			     int maxf, int *nf)
{
	const char *p = s;
	const char *end = s + len;
	int n = 0;

	memset(f, 0, sizeof(*f) * (size_t)maxf);
	skip_ws(&p, end);
	if (p >= end || *p != '{')
		return -1;
	p++;
	skip_ws(&p, end);
	if (p < end && *p == '}') {
		p++;
		skip_ws(&p, end);
		if (p != end)
			return -1;
		*nf = 0;
		return 0;
	}

	for (;;) {
		char key[JF_KEY];
		int i, dup = 0;

		if (n >= maxf)
			return -1;
		if (json_string(&p, end, key, sizeof(key)) < 0)
			return -1;
		for (i = 0; i < n; i++) {
			if (strcmp(f[i].key, key) == 0)
				dup = 1;
		}
		if (dup)
			return -1;
		skip_ws(&p, end);
		if (p >= end || *p != ':')
			return -1;
		p++;
		skip_ws(&p, end);
		strcpy(f[n].key, key);

		if (p < end && *p == '"') {
			f[n].type = JF_STR;
			if (json_string(&p, end, f[n].s, sizeof(f[n].s)) < 0)
				return -1;
		} else if (p < end && (*p == '-' || isdigit((unsigned char)*p))) {
			f[n].type = JF_INT;
			if (json_integer(&p, end, &f[n].n) < 0)
				return -1;
		} else {
			return -1;
		}
		n++;
		skip_ws(&p, end);
		if (p < end && *p == ',') {
			p++;
			skip_ws(&p, end);
			continue;
		}
		if (p < end && *p == '}') {
			p++;
			break;
		}
		return -1;
	}
	skip_ws(&p, end);
	if (p != end)
		return -1;
	*nf = n;
	return 0;
}

static struct jfield *jf_find(struct jfield *f, int nf, const char *key)
{
	int i;

	for (i = 0; i < nf; i++) {
		if (strcmp(f[i].key, key) == 0)
			return &f[i];
	}
	return NULL;
}

/* ------------------------------------------------------------------------- */
/* JWT HS256                                                                 */
/* ------------------------------------------------------------------------- */

struct claims {
	char sub[64];
	char scope[128];
	char jti[64];
	long exp;
	long iat;
};

enum jwt_result { JWT_OK = 0, JWT_BAD = 1, JWT_EXPIRED = 2 };

static int random_hex(char *out, size_t bytes)
{
	unsigned char buf[32];
	int fd, i;
	size_t got = 0;

	if (bytes > sizeof(buf))
		return -1;
	fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	while (got < bytes) {
		ssize_t n = read(fd, buf + got, bytes - got);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			return -1;
		}
		if (n == 0) {
			close(fd);
			return -1;
		}
		got += (size_t)n;
	}
	close(fd);
	for (i = 0; i < (int)bytes; i++)
		snprintf(out + i * 2, 3, "%02x", buf[i]);
	out[bytes * 2] = '\0';
	memset(buf, 0, sizeof(buf));
	return 0;
}

static int scope_is_allowed(const char *scope)
{
	char tmp[128];
	char *save = NULL;
	char *tok;
	int any = 0;

	if (strlen(scope) >= sizeof(tmp))
		return 0;
	strcpy(tmp, scope);
	for (tok = strtok_r(tmp, " ", &save); tok; tok = strtok_r(NULL, " ", &save)) {
		if (strcmp(tok, "read") != 0 && strcmp(tok, "transfer") != 0)
			return 0;
		any = 1;
	}
	return any;
}

static int scope_has(const char *scope, const char *need)
{
	const char *p = scope;
	size_t needlen = strlen(need);

	while (*p) {
		const char *start;
		size_t len;
		while (*p == ' ')
			p++;
		start = p;
		while (*p && *p != ' ')
			p++;
		len = (size_t)(p - start);
		if (len == needlen && memcmp(start, need, len) == 0)
			return 1;
	}
	return 0;
}

static int jwt_issue(const char *sub, const char *scope, char *out, size_t cap)
{
	static const char header[] = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
	char payload[768];
	char hb64[128], pb64[1024], sb64[64];
	char signing[1200];
	char jti[64];
	unsigned char mac[32];
	long now = (long)time(NULL);
	int n;

	if (random_hex(jti, 16) < 0)
		return -1;
	n = snprintf(payload, sizeof(payload),
		     "{\"iss\":\"%s\",\"aud\":\"%s\",\"sub\":\"%s\","
		     "\"scope\":\"%s\",\"iat\":%ld,\"exp\":%ld,\"jti\":\"%s\"}",
		     JWT_ISSUER, JWT_AUDIENCE, sub, scope,
		     now, now + JWT_TTL, jti);
	if (n < 0 || (size_t)n >= sizeof(payload))
		return -1;

	if (b64url_encode((const unsigned char *)header, strlen(header),
			  hb64, sizeof(hb64)) == 0)
		return -1;
	if (b64url_encode((const unsigned char *)payload, strlen(payload),
			  pb64, sizeof(pb64)) == 0)
		return -1;
	n = snprintf(signing, sizeof(signing), "%s.%s", hb64, pb64);
	if (n < 0 || (size_t)n >= sizeof(signing))
		return -1;

	if (hmac_sha256((const unsigned char *)g_jwt_secret,
			strlen(g_jwt_secret),
			(const unsigned char *)signing, strlen(signing),
			mac) < 0)
		return -1;
	if (b64url_encode(mac, sizeof(mac), sb64, sizeof(sb64)) == 0)
		return -1;

	n = snprintf(out, cap, "%s.%s", signing, sb64);
	if (n < 0 || (size_t)n >= cap)
		return -1;
	return 0;
}

static int jwt_verify(const char *token, struct claims *out)
{
	const char *dot1, *dot2;
	size_t hlen, plen, slen;
	size_t hlen_dec = 0, plen_dec = 0, slen_dec = 0;
	char hdr[512], payload[1024];
	unsigned char sig[64], mac[32];
	struct jfield hf[8], pf[JF_MAX];
	struct jfield *f;
	int nh = 0, np = 0;
	long now;

	if (strlen(token) >= JWT_MAX)
		return JWT_BAD;
	dot1 = strchr(token, '.');
	if (!dot1)
		return JWT_BAD;
	dot2 = strchr(dot1 + 1, '.');
	if (!dot2 || strchr(dot2 + 1, '.'))
		return JWT_BAD;
	hlen = (size_t)(dot1 - token);
	plen = (size_t)(dot2 - dot1 - 1);
	slen = strlen(dot2 + 1);
	if (hlen == 0 || plen == 0 || slen == 0 || hlen >= sizeof(hdr) ||
	    plen >= sizeof(payload))
		return JWT_BAD;

	if (b64url_decode(token, hlen, (unsigned char *)hdr,
			  sizeof(hdr) - 1, &hlen_dec) < 0)
		return JWT_BAD;
	hdr[hlen_dec] = '\0';
	if (b64url_decode(dot1 + 1, plen, (unsigned char *)payload,
			  sizeof(payload) - 1, &plen_dec) < 0)
		return JWT_BAD;
	payload[plen_dec] = '\0';
	if (b64url_decode(dot2 + 1, slen, sig, sizeof(sig), &slen_dec) < 0 ||
	    slen_dec != sizeof(mac))
		return JWT_BAD;

	if (json_parse_object(hdr, strlen(hdr), hf, 8, &nh) < 0)
		return JWT_BAD;
	f = jf_find(hf, nh, "alg");
	if (!f || f->type != JF_STR || strcmp(f->s, "HS256") != 0)
		return JWT_BAD;
	f = jf_find(hf, nh, "typ");
	if (f && (f->type != JF_STR || strcmp(f->s, "JWT") != 0))
		return JWT_BAD;

	if (hmac_sha256((const unsigned char *)g_jwt_secret,
			strlen(g_jwt_secret),
			(const unsigned char *)token,
			(size_t)(dot2 - token), mac) < 0)
		return JWT_BAD;
	if (!ct_equal(mac, sig, sizeof(mac)))
		return JWT_BAD;

	if (json_parse_object(payload, strlen(payload), pf, JF_MAX, &np) < 0)
		return JWT_BAD;
	f = jf_find(pf, np, "iss");
	if (!f || f->type != JF_STR || strcmp(f->s, JWT_ISSUER) != 0)
		return JWT_BAD;
	f = jf_find(pf, np, "aud");
	if (!f || f->type != JF_STR || strcmp(f->s, JWT_AUDIENCE) != 0)
		return JWT_BAD;
	f = jf_find(pf, np, "sub");
	if (!f || f->type != JF_STR || f->s[0] == '\0' ||
	    strlen(f->s) >= sizeof(out->sub))
		return JWT_BAD;
	strcpy(out->sub, f->s);
	f = jf_find(pf, np, "scope");
	if (!f || f->type != JF_STR || f->s[0] == '\0' ||
	    strlen(f->s) >= sizeof(out->scope))
		return JWT_BAD;
	strcpy(out->scope, f->s);
	f = jf_find(pf, np, "jti");
	if (!f || f->type != JF_STR || f->s[0] == '\0' ||
	    strlen(f->s) >= sizeof(out->jti))
		return JWT_BAD;
	strcpy(out->jti, f->s);

	f = jf_find(pf, np, "exp");
	if (!f || f->type != JF_INT)
		return JWT_BAD;
	out->exp = f->n;
	f = jf_find(pf, np, "iat");
	if (!f || f->type != JF_INT)
		return JWT_BAD;
	out->iat = f->n;

	now = (long)time(NULL);
	if (out->exp <= now)
		return JWT_EXPIRED;
	if (out->iat > now + JWT_CLOCK_SKEW)
		return JWT_BAD;
	if (out->exp < out->iat ||
	    out->exp - out->iat > JWT_MAX_LIFETIME + JWT_CLOCK_SKEW)
		return JWT_BAD;
	return JWT_OK;
}

/* ------------------------------------------------------------------------- */
/* Rate limiting: ventana fija por clave, tabla hash con sondeo lineal       */
/* ------------------------------------------------------------------------- */

struct rl_slot {
	char key[96];
	uint64_t window;
	unsigned count;
	int used;
};

static struct rl_slot rl_table[RATE_SLOTS];

static uint64_t fnv1a(const char *s)
{
	uint64_t h = 1469598103934665603ULL;

	while (*s) {
		h ^= (unsigned char)*s++;
		h *= 1099511628211ULL;
	}
	return h;
}

static int rate_allow(const char *key, int limit, int window_s, int *retry_after)
{
	time_t now = time(NULL);
	uint64_t win = (uint64_t)now / (uint64_t)window_s;
	size_t i = (size_t)(fnv1a(key) % RATE_SLOTS);
	size_t probes;

	if (limit <= 0)
		return 1;

	for (probes = 0; probes < RATE_SLOTS; probes++) {
		struct rl_slot *s = &rl_table[i];

		if (!s->used) {
			memset(s, 0, sizeof(*s));
			strncpy(s->key, key, sizeof(s->key) - 1);
			s->used = 1;
			s->window = win;
		}
		if (strcmp(s->key, key) == 0) {
			if (s->window != win) {
				s->window = win;
				s->count = 0;
			}
			if (s->count >= (unsigned)limit) {
				*retry_after = window_s - (int)(now % window_s);
				return 0;
			}
			s->count++;
			return 1;
		}
		i = (i + 1) % RATE_SLOTS;
	}

	/* Tabla llena: fallar cerrado. */
	*retry_after = window_s;
	return 0;
}

/* ------------------------------------------------------------------------- */
/* HTTP mínimo                                                               */
/* ------------------------------------------------------------------------- */

#define RAW_MAX (HTTP_HEADER_MAX + HTTP_BODY_MAX + 1)

struct request {
	char method[8];
	char path[512];
	char peer[64];
	char auth[1024];
	char ctype[160];
	long content_length;
	char body[HTTP_BODY_MAX + 1];
};

static const char *status_reason(int code)
{
	switch (code) {
	case 200: return "OK";
	case 201: return "Created";
	case 400: return "Bad Request";
	case 401: return "Unauthorized";
	case 403: return "Forbidden";
	case 404: return "Not Found";
	case 405: return "Method Not Allowed";
	case 408: return "Request Timeout";
	case 413: return "Payload Too Large";
	case 414: return "URI Too Long";
	case 415: return "Unsupported Media Type";
	case 429: return "Too Many Requests";
	case 431: return "Request Header Fields Too Large";
	case 500: return "Internal Server Error";
	case 503: return "Service Unavailable";
	default: return "Error";
	}
}

static int send_all(int fd, const char *buf, size_t len)
{
	size_t off = 0;

	while (off < len) {
		ssize_t n = send(fd, buf + off, len - off, 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		off += (size_t)n;
	}
	return 0;
}

static void respond(int fd, int status, const char *ctype,
		    const char *extra, const char *body)
{
	char hdr[1024];
	size_t blen = strlen(body);
	int n = snprintf(hdr, sizeof(hdr),
			 "HTTP/1.1 %d %s\r\n"
			 "Content-Type: %s\r\n"
			 "Content-Length: %zu\r\n"
			 "X-Content-Type-Options: nosniff\r\n"
			 "Cache-Control: no-store\r\n"
			 "Connection: close\r\n"
			 "%s"
			 "\r\n",
			 status, status_reason(status), ctype, blen,
			 extra ? extra : "");
	if (n < 0 || (size_t)n >= sizeof(hdr))
		return;
	send_all(fd, hdr, (size_t)n);
	send_all(fd, body, blen);
}

static void respond_error(int fd, int status, const char *code)
{
	char body[160];
	int n = snprintf(body, sizeof(body),
			 "{\"error\":\"%s\"}", code);
	if (n < 0 || (size_t)n >= sizeof(body))
		return;
	respond(fd, status, "application/json", NULL, body);
}

static char *trim(char *s)
{
	char *e;

	while (*s && isspace((unsigned char)*s))
		s++;
	e = s + strlen(s);
	while (e > s && isspace((unsigned char)e[-1]))
		*--e = '\0';
	return s;
}

static int copy_str(char *dst, size_t cap, const char *src)
{
	size_t n = strlen(src);

	if (n >= cap)
		return -1;
	memcpy(dst, src, n + 1);
	return 0;
}

static int recv_request(int fd, struct request *rq, char *raw, size_t rawcap)
{
	size_t n = 0;
	char *hdr_end = NULL;
	char *line, *save_line, *save_hdr;
	char *method, *target, *version;
	long clen = -1;
	int chunked = 0;

	memset(rq, 0, sizeof(*rq));
	for (;;) {
		ssize_t r;
		if (n >= HTTP_HEADER_MAX)
			return 431;
		r = recv(fd, raw + n, rawcap - 1 - n, 0);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return 408;
		}
		if (r == 0)
			return 400;
		n += (size_t)r;
		raw[n] = '\0';
		hdr_end = strstr(raw, "\r\n\r\n");
		if (hdr_end)
			break;
	}
	*hdr_end = '\0';

	line = strtok_r(raw, "\r\n", &save_hdr);
	if (!line)
		return 400;
	method = strtok_r(line, " ", &save_line);
	target = strtok_r(NULL, " ", &save_line);
	version = strtok_r(NULL, " ", &save_line);
	if (!method || !target || !version || strtok_r(NULL, " ", &save_line))
		return 400;
	if (strcmp(version, "HTTP/1.1") != 0 && strcmp(version, "HTTP/1.0") != 0)
		return 400;
	if (strlen(method) >= sizeof(rq->method))
		return 400;
	strcpy(rq->method, method);
	if (target[0] != '/')
		return 400;
	{
		size_t plen = strcspn(target, "?");
		if (plen >= sizeof(rq->path))
			return 414;
		memcpy(rq->path, target, plen);
		rq->path[plen] = '\0';
	}

	while ((line = strtok_r(NULL, "\r\n", &save_hdr)) != NULL) {
		char *colon = strchr(line, ':');
		char *name, *value;
		if (!colon)
			return 400;
		*colon = '\0';
		name = trim(line);
		value = trim(colon + 1);
		if (strcasecmp(name, "Authorization") == 0) {
			if (copy_str(rq->auth, sizeof(rq->auth), value) < 0)
				return 431;
		} else if (strcasecmp(name, "Content-Type") == 0) {
			if (copy_str(rq->ctype, sizeof(rq->ctype), value) < 0)
				return 431;
		} else if (strcasecmp(name, "Content-Length") == 0) {
			char *endp = NULL;
			long v = strtol(value, &endp, 10);
			if (!endp || *endp != '\0' || v < 0)
				return 400;
			clen = v;
		} else if (strcasecmp(name, "Transfer-Encoding") == 0) {
			chunked = 1;
		}
	}
	if (chunked)
		return 400;
	if (clen > HTTP_BODY_MAX) {
		/* Drenar un poco antes de cerrar evita RST en clientes educados. */
		char sink[1024];
		long left = clen > 65536 ? 65536 : clen;
		while (left > 0) {
			size_t want = (size_t)left < sizeof(sink) ? (size_t)left : sizeof(sink);
			ssize_t r = recv(fd, sink, want, 0);
			if (r <= 0)
				break;
			left -= r;
		}
		return 413;
	}
	if (clen < 0)
		clen = 0;
	rq->content_length = clen;

	{
		size_t hlen = (size_t)(hdr_end - raw) + 4;
		size_t have = n - hlen;

		if (have > (size_t)clen)
			have = (size_t)clen;
		if (have > 0)
			memcpy(rq->body, raw + hlen, have);
		while (have < (size_t)clen) {
			ssize_t r = recv(fd, rq->body + have,
					 (size_t)clen - have, 0);
			if (r < 0) {
				if (errno == EINTR)
					continue;
				return 408;
			}
			if (r == 0)
				return 400;
			have += (size_t)r;
		}
		rq->body[have] = '\0';
	}
	return 0;
}

static void peer_name(int fd, char *out, size_t cap)
{
	struct sockaddr_storage ss;
	socklen_t sl = sizeof(ss);

	if (getpeername(fd, (struct sockaddr *)&ss, &sl) < 0) {
		strncpy(out, "unknown", cap - 1);
		out[cap - 1] = '\0';
		return;
	}
	if (ss.ss_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
		inet_ntop(AF_INET, &sin->sin_addr, out, (socklen_t)cap);
	} else if (ss.ss_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
		inet_ntop(AF_INET6, &sin6->sin6_addr, out, (socklen_t)cap);
	} else {
		strncpy(out, "unknown", cap - 1);
		out[cap - 1] = '\0';
	}
}

/* ------------------------------------------------------------------------- */
/* OAuth 2.0: application/x-www-form-urlencoded                              */
/* ------------------------------------------------------------------------- */

struct kv {
	char k[64];
	char v[256];
};

static int url_decode(const char *in, size_t len, char *out, size_t cap)
{
	size_t i, o = 0;

	for (i = 0; i < len; i++) {
		unsigned char c = (unsigned char)in[i];
		if (c == '+') {
			c = ' ';
		} else if (c == '%') {
			int a, b;
			if (i + 2 >= len)
				return -1;
			a = hexval((unsigned char)in[i + 1]);
			b = hexval((unsigned char)in[i + 2]);
			if (a < 0 || b < 0)
				return -1;
			c = (unsigned char)((a << 4) | b);
			i += 2;
		}
		if (c == '\0')
			return -1;
		if (o + 1 >= cap)
			return -1;
		out[o++] = (char)c;
	}
	out[o] = '\0';
	return 0;
}

static int parse_form(const char *body, size_t len, struct kv *kv, int max, int *nkv)
{
	size_t pos = 0;
	int n = 0;

	while (pos < len) {
		size_t amp = pos;
		size_t eq;
		int i, dup = 0;

		while (amp < len && body[amp] != '&')
			amp++;
		if (amp == pos)
			return -1;
		eq = pos;
		while (eq < amp && body[eq] != '=')
			eq++;
		if (eq == amp)
			return -1;
		if (n >= max)
			return -1;
		if (url_decode(body + pos, eq - pos, kv[n].k, sizeof(kv[n].k)) < 0)
			return -1;
		if (url_decode(body + eq + 1, amp - eq - 1,
			       kv[n].v, sizeof(kv[n].v)) < 0)
			return -1;
		if (kv[n].k[0] == '\0')
			return -1;
		for (i = 0; i < n; i++) {
			if (strcmp(kv[i].k, kv[n].k) == 0)
				dup = 1;
		}
		if (dup)
			return -1;
		n++;
		pos = amp + (amp < len ? 1 : 0);
	}
	*nkv = n;
	return 0;
}

static int ctype_is(const char *actual, const char *expected)
{
	size_t n = strlen(expected);

	if (strncasecmp(actual, expected, n) != 0)
		return 0;
	return actual[n] == '\0' || actual[n] == ';';
}

static const char *kv_get(struct kv *kv, int nkv, const char *key)
{
	int i;

	for (i = 0; i < nkv; i++) {
		if (strcmp(kv[i].k, key) == 0)
			return kv[i].v;
	}
	return NULL;
}

static int client_ok(const char *id, const char *secret)
{
	int a = ct_streq(id, OAUTH_CLIENT_ID);
	int b = ct_streq(secret, g_client_secret);
	return a & b;
}

/* ------------------------------------------------------------------------- */
/* Validación de la transferencia                                            */
/* ------------------------------------------------------------------------- */

static int valid_account(const char *s)
{
	size_t i;

	if (strlen(s) != 8)
		return 0;
	for (i = 0; i < 3; i++) {
		if (!(s[i] >= 'A' && s[i] <= 'Z'))
			return 0;
	}
	if (s[3] != '-')
		return 0;
	for (i = 4; i < 8; i++) {
		if (!isdigit((unsigned char)s[i]))
			return 0;
	}
	return 1;
}

static int validate_transfer(const struct request *rq, char *account,
			     size_t acccap, long *amount, const char **err)
{
	struct jfield f[JF_MAX];
	struct jfield *af, *mf;
	int nf = 0;

	if (json_parse_object(rq->body, (size_t)rq->content_length,
			      f, JF_MAX, &nf) < 0) {
		*err = "invalid_json";
		return -1;
	}
	if (nf != 2) {
		*err = "unexpected_fields";
		return -1;
	}
	af = jf_find(f, nf, "account");
	mf = jf_find(f, nf, "amount");
	if (!af || !mf) {
		*err = "missing_field";
		return -1;
	}
	if (af->type != JF_STR || !valid_account(af->s)) {
		*err = "invalid_account";
		return -1;
	}
	if (mf->type != JF_INT || mf->n < 1 || mf->n > 1000000) {
		*err = "invalid_amount";
		return -1;
	}
	if (copy_str(account, acccap, af->s) < 0) {
		*err = "invalid_account";
		return -1;
	}
	*amount = mf->n;
	return 0;
}

/* ------------------------------------------------------------------------- */
/* Rutas                                                                     */
/* ------------------------------------------------------------------------- */

static int authenticate(const struct request *rq, const char *need_scope,
			struct claims *cl)
{
	const char *tok;

	if (strncasecmp(rq->auth, "Bearer ", 7) != 0)
		return 401;
	tok = rq->auth + 7;
	while (*tok == ' ')
		tok++;
	if (*tok == '\0')
		return 401;
	if (jwt_verify(tok, cl) != JWT_OK)
		return 401;
	if (need_scope && !scope_has(cl->scope, need_scope))
		return 403;
	return 0;
}

static int handle_request(int fd, struct request *rq)
{
	int retry = 0;
	char key[128];

	if (strcmp(rq->method, "GET") == 0 && strcmp(rq->path, "/healthz") == 0) {
		respond(fd, 200, "application/json", NULL, "{\"status\":\"ok\"}");
		return 200;
	}

	if (strcmp(rq->path, "/oauth/token") == 0) {
		struct kv kv[16];
		const char *grant, *id, *secret, *scope;
		char token[JWT_MAX];
		char body[1200];
		int nkv = 0, n;

		if (strcmp(rq->method, "POST") != 0) {
			respond_error(fd, 405, "method_not_allowed");
			return 405;
		}
		if (!ctype_is(rq->ctype, "application/x-www-form-urlencoded")) {
			respond_error(fd, 415, "unsupported_media_type");
			return 415;
		}
		snprintf(key, sizeof(key), "ip:token:%s", rq->peer);
		if (!rate_allow(key, g_rate_limit, g_rate_window, &retry)) {
			char extra[64];
			snprintf(extra, sizeof(extra),
				 "Retry-After: %d\r\n", retry);
			respond(fd, 429, "application/json", extra,
				"{\"error\":\"rate_limited\"}");
			return 429;
		}
		if (parse_form(rq->body, (size_t)rq->content_length, kv, 16, &nkv) < 0) {
			respond_error(fd, 400, "invalid_request");
			return 400;
		}
		grant = kv_get(kv, nkv, "grant_type");
		id = kv_get(kv, nkv, "client_id");
		secret = kv_get(kv, nkv, "client_secret");
		scope = kv_get(kv, nkv, "scope");
		if (!grant || strcmp(grant, "client_credentials") != 0) {
			respond_error(fd, 400, "unsupported_grant_type");
			return 400;
		}
		if (!id || !secret) {
			respond_error(fd, 400, "invalid_request");
			return 400;
		}
		if (!client_ok(id, secret)) {
			respond_error(fd, 401, "invalid_client");
			return 401;
		}
		if (!scope || *scope == '\0')
			scope = OAUTH_SCOPE_DEFAULT;
		if (!scope_is_allowed(scope)) {
			respond_error(fd, 400, "invalid_scope");
			return 400;
		}
		if (jwt_issue(id, scope, token, sizeof(token)) < 0) {
			respond_error(fd, 500, "server_error");
			return 500;
		}
		n = snprintf(body, sizeof(body),
			     "{\"access_token\":\"%s\",\"token_type\":\"Bearer\","
			     "\"expires_in\":%d,\"scope\":\"%s\"}",
			     token, JWT_TTL, scope);
		if (n < 0 || (size_t)n >= sizeof(body)) {
			respond_error(fd, 500, "server_error");
			return 500;
		}
		respond(fd, 200, "application/json; charset=utf-8",
			"Pragma: no-cache\r\n", body);
		return 200;
	}

	if (strcmp(rq->path, "/api/v1/profile") == 0 ||
	    strcmp(rq->path, "/api/v1/transfers") == 0) {
		struct claims cl;
		int status;

		snprintf(key, sizeof(key), "ip:api:%s", rq->peer);
		if (!rate_allow(key, g_rate_limit, g_rate_window, &retry)) {
			char extra[64];
			snprintf(extra, sizeof(extra),
				 "Retry-After: %d\r\n", retry);
			respond(fd, 429, "application/json", extra,
				"{\"error\":\"rate_limited\"}");
			return 429;
		}
		status = authenticate(rq, NULL, &cl);
		if (status != 0) {
			respond(fd, status, "application/json",
				status == 401 ?
				"WWW-Authenticate: Bearer realm=\"a4-api\"\r\n" : NULL,
				status == 401 ?
				"{\"error\":\"invalid_token\"}" :
				"{\"error\":\"forbidden\"}");
			return status;
		}
		snprintf(key, sizeof(key), "sub:%s", cl.sub);
		if (!rate_allow(key, g_rate_limit, g_rate_window, &retry)) {
			char extra[64];
			snprintf(extra, sizeof(extra),
				 "Retry-After: %d\r\n", retry);
			respond(fd, 429, "application/json", extra,
				"{\"error\":\"rate_limited\"}");
			return 429;
		}

		if (strcmp(rq->path, "/api/v1/profile") == 0) {
			char body[320];
			int n;

			if (strcmp(rq->method, "GET") != 0) {
				respond_error(fd, 405, "method_not_allowed");
				return 405;
			}
			if (!scope_has(cl.scope, "read")) {
				respond_error(fd, 403, "insufficient_scope");
				return 403;
			}
			n = snprintf(body, sizeof(body),
				     "{\"sub\":\"%s\",\"scope\":\"%s\",\"jti\":\"%s\"}",
				     cl.sub, cl.scope, cl.jti);
			if (n < 0 || (size_t)n >= sizeof(body)) {
				respond_error(fd, 500, "server_error");
				return 500;
			}
			respond(fd, 200, "application/json", NULL, body);
			return 200;
		}

		/* /api/v1/transfers */
		if (strcmp(rq->method, "POST") != 0) {
			respond_error(fd, 405, "method_not_allowed");
			return 405;
		}
		if (!ctype_is(rq->ctype, "application/json")) {
			respond_error(fd, 415, "unsupported_media_type");
			return 415;
		}
		if (!scope_has(cl.scope, "transfer")) {
			respond_error(fd, 403, "insufficient_scope");
			return 403;
		}
		{
			char account[16];
			long amount = 0;
			const char *err = NULL;
			char body[256];
			int n;

			if (validate_transfer(rq, account, sizeof(account),
					      &amount, &err) < 0) {
				char ebody[96];
				n = snprintf(ebody, sizeof(ebody),
					     "{\"error\":\"validation_failed\",\"field\":\"%s\"}",
					     err);
				if (n > 0 && (size_t)n < sizeof(ebody))
					respond(fd, 400, "application/json", NULL, ebody);
				else
					respond_error(fd, 400, "validation_failed");
				return 400;
			}
			n = snprintf(body, sizeof(body),
				     "{\"status\":\"accepted\",\"account\":\"%s\","
				     "\"amount\":%ld}",
				     account, amount);
			if (n < 0 || (size_t)n >= sizeof(body)) {
				respond_error(fd, 500, "server_error");
				return 500;
			}
			respond(fd, 200, "application/json", NULL, body);
			return 200;
		}
	}

	respond_error(fd, 404, "not_found");
	return 404;
}

static void handle_client(int fd)
{
	char raw[RAW_MAX];
	struct request rq;
	struct timeval tv = { REQ_TIMEOUT_SEC, 0 };
	int status;

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	status = recv_request(fd, &rq, raw, sizeof(raw));
	peer_name(fd, rq.peer, sizeof(rq.peer));
	if (status != 0) {
		respond_error(fd, status, status == 413 ? "payload_too_large" :
			      status == 431 ? "headers_too_large" :
			      status == 414 ? "uri_too_long" :
			      status == 408 ? "timeout" : "bad_request");
		fprintf(stderr, "%s - -> %d\n", rq.peer, status);
		return;
	}
	status = handle_request(fd, &rq);
	fprintf(stderr, "%s %s %s -> %d\n", rq.peer, rq.method, rq.path, status);
}

static int env_int(const char *name, int def)
{
	const char *v = getenv(name);
	char *end = NULL;
	long x;

	if (!v || *v == '\0')
		return def;
	x = strtol(v, &end, 10);
	if (!end || *end != '\0' || x < 1 || x > 1000000)
		return def;
	return (int)x;
}

int main(void)
{
	struct sockaddr_in addr;
	int sfd, one = 1;
	int port;

	signal(SIGPIPE, SIG_IGN);

	if (getenv("A4_JWT_SECRET"))
		g_jwt_secret = getenv("A4_JWT_SECRET");
	if (getenv("A4_CLIENT_SECRET"))
		g_client_secret = getenv("A4_CLIENT_SECRET");
	g_rate_limit = env_int("A4_RATE_LIMIT", RATE_LIMIT);
	g_rate_window = env_int("A4_RATE_WINDOW", RATE_WINDOW);
	port = env_int("A4_PORT", LISTEN_PORT);

	if (strcmp(g_jwt_secret, JWT_SECRET_DEFAULT) == 0)
		fprintf(stderr, "aviso: usando A4_JWT_SECRET de laboratorio\n");

	sfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sfd < 0) {
		perror("socket");
		return 1;
	}
	setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons((uint16_t)port);
	if (inet_pton(AF_INET, LISTEN_ADDR, &addr.sin_addr) != 1) {
		fprintf(stderr, "dirección inválida: %s\n", LISTEN_ADDR);
		return 1;
	}
	if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		return 1;
	}
	if (listen(sfd, 32) < 0) {
		perror("listen");
		return 1;
	}
	fprintf(stderr, "a4-api escuchando en http://%s:%d (rate=%d/%ds)\n",
		LISTEN_ADDR, port, g_rate_limit, g_rate_window);

	for (;;) {
		int cfd = accept(sfd, NULL, NULL);
		if (cfd < 0) {
			if (errno == EINTR)
				continue;
			perror("accept");
			continue;
		}
		handle_client(cfd);
		close(cfd);
	}
}
