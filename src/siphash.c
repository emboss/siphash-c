#include <string.h>
#include <stdio.h>
#include "siphash.h"

#ifdef _WIN32
  #define BYTE_ORDER __LITTLE_ENDIAN
#elif !defined BYTE_ORDER
  #include <endian.h>
#endif
#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN __LITTLE_ENDIAN
#endif
#ifndef BIG_ENDIAN
#define BIG_ENDIAN __BIG_ENDIAN
#endif

#ifndef UNALIGNED_WORD_ACCESS
# if defined(__i386) || defined(__i386__) || defined(_M_IX86) || \
     defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD86) || \
     defined(__mc68020__)
#   define UNALIGNED_WORD_ACCESS 1
# endif
#endif
#ifndef UNALIGNED_WORD_ACCESS
# define UNALIGNED_WORD_ACCESS 0
#endif

#define U8TO32_LE(p)         						\
    (((uint32_t)((p)[0])       ) | ((uint32_t)((p)[1]) <<  8) |  	\
     ((uint32_t)((p)[2]) <<  16) | ((uint32_t)((p)[3]) << 24))		\

#define U32TO8_LE(p, v)			\
do {					\
    (p)[0] = (uint8_t)((v)      );	\
    (p)[1] = (uint8_t)((v) >>  8); 	\
    (p)[2] = (uint8_t)((v) >> 16);	\
    (p)[3] = (uint8_t)((v) >> 24);	\
} while (0)

#define U8TO64_LE(p) 							\
    ((uint64_t)U8TO32_LE(p) | ((uint64_t)U8TO32_LE((p) + 4)) << 32 )

#define U64TO8_LE(p, v) \
do {						\
    U32TO8_LE((p),     (uint32_t)((v)      )); 	\
    U32TO8_LE((p) + 4, (uint32_t)((v) >> 32));	\
} while (0)

#define ROTL64(v, s)			\
    ((v) << (s)) | ((v) >> (64 - (s)))

typedef struct {
  int c;
  int d;
  uint64_t v[4];
  uint8_t buf[sizeof(uint64_t)];
  uint8_t buflen;
  uint8_t msglen_byte;
} sip_state;

static const uint64_t sip_init_state[4] = {
    0x736f6d6570736575ULL,
    0x646f72616e646f6dULL,
    0x6c7967656e657261ULL,
    0x7465646279746573ULL
};

typedef struct {
    void (*init)(sip_state *s, uint8_t *key);
    void (*update)(sip_state *s, uint8_t *data, size_t len);
    void (*final)(sip_state *s, uint64_t *digest);
} sip_interface;

struct sip_hash_st {
    sip_state *state;
    sip_interface *methods;
};

static void int_sip_init(sip_state *state, uint8_t *key);
static void int_sip_update(sip_state *state, uint8_t *data, size_t len);
static void int_sip_final(sip_state *state, uint64_t *digest);

static sip_interface sip_methods = {
    int_sip_init,
    int_sip_update,
    int_sip_final
};

#define SIP_COMPRESS(v0, v1, v2, v3)	\
do {					\
    (v0) += (v1);			\
    (v2) += (v3);			\
    (v1) = ROTL64((v1), 13);		\
    (v3) = ROTL64((v3), 16);		\
    (v1) ^= (v0);			\
    (v3) ^= (v2);			\
    (v0) = ROTL64((v0), 32);		\
    (v2) += (v1);			\
    (v0) += (v3);			\
    (v1) = ROTL64((v1), 17);		\
    (v3) = ROTL64((v3), 21);		\
    (v1) ^= (v2);			\
    (v3) ^= (v0);			\
    (v2) = ROTL64((v2), 32);		\
} while(0)

static void
int_sip_dump(sip_state *state)
{
    int v;

    for (v = 0; v < 4; v++) {
	printf("v%d: %" PRIx64 "\n", v, state->v[v]);
    }
}

static void
int_sip_init(sip_state *state, uint8_t key[16])
{
    uint64_t k0, k1;

    k0 = U8TO64_LE(key);
    k1 = U8TO64_LE(key + sizeof(uint64_t));

    state->v[0] = k0 ^ sip_init_state[0];
    state->v[1] = k1 ^ sip_init_state[1];
    state->v[2] = k0 ^ sip_init_state[2];
    state->v[3] = k1 ^ sip_init_state[3];
}

static inline void
int_sip_round(sip_state *state, int n)
{
    int i;

    for (i = 0; i < n; i++) {
	SIP_COMPRESS(state->v[0], state->v[1], state->v[2], state->v[3]);
    }
}

static inline void
int_sip_update_block(sip_state *state, uint64_t m)
{
    state->v[3] ^= m;
    int_sip_round(state, state->c);
    state->v[0] ^= m;
}

static inline void
int_sip_pre_update(sip_state *state, uint8_t **pdata, size_t *plen)
{
    int to_read;
    uint64_t m;

    if (!state->buflen) return;

    to_read = sizeof(uint64_t) - state->buflen;
    memcpy(state->buf + state->buflen, *pdata, to_read);
    m = U8TO64_LE(state->buf);
    int_sip_update_block(state, m);
    *pdata += to_read;
    *plen -= to_read;
    state->buflen = 0;
}

static inline void
int_sip_post_update(sip_state *state, uint8_t *data, size_t len)
{
    uint8_t r = len % sizeof(uint64_t);
    if (r) {
	memcpy(state->buf, data + len - r, r);
	state->buflen = r;
    }
}

static void
int_sip_update(sip_state *state, uint8_t *data, size_t len)
{
    uint64_t *end;
    uint64_t *data64;

    state->msglen_byte = state->msglen_byte + (len % 256);
    data64 = (uint64_t *) data;

    int_sip_pre_update(state, &data, &len);

    end = data64 + (len / sizeof(uint64_t));

#if BYTE_ORDER == LITTLE_ENDIAN
    while (data64 != end) {
	int_sip_update_block(state, *data64++);
    }
#elif BYTE_ORDER == BIG_ENDIAN
    {
	uint64_t m;
	uint8_t *data8 = data;
	for (; data8 != (uint8_t *) end; data8 += sizeof(uint64_t)) {
	    m = U8TO64_LE(data8);
	    int_sip_update_block(state, m);
	}
    }
#else
  #error "Only strictly little or big endian supported"
#endif

    int_sip_post_update(state, data, len);
}

static inline void
int_sip_pad_final_block(sip_state *state)
{
    int i;
    //pad with 0's and finalize with msg_len mod 256
    for (i = state->buflen; i < sizeof(uint64_t); i++) {
	state->buf[i] = 0x00;
    }
    state->buf[sizeof(uint64_t) - 1] = state->msglen_byte;
}

static void
int_sip_final(sip_state *state, uint64_t *digest)
{
    uint64_t m;

    int_sip_pad_final_block(state);

    m = U8TO64_LE(state->buf);
    int_sip_update_block(state, m);

    state->v[2] ^= 0xff;

    int_sip_round(state, state->d);

    *digest = state->v[0] ^ state->v[1] ^ state->v[2] ^ state->v[3];
}

sip_hash *
sip_hash_new(uint8_t key[16], int c, int d)
{
    sip_hash *h = NULL;

    if (!(h = (sip_hash *) malloc(sizeof(sip_hash)))) return NULL;
    h->state = NULL;
    if (!(h->state = (sip_state *) malloc(sizeof(sip_state)))) return NULL;
    h->state->c = c;
    h->state->d = d;
    h->state->buflen = 0;
    h->state->msglen_byte = 0;
    h->methods = &sip_methods;
    h->methods->init(h->state, key);
    return h;
}

int
sip_hash_update(sip_hash *h, uint8_t *msg, size_t len)
{
    h->methods->update(h->state, msg, len);
    return 1;
}

int
sip_hash_final(sip_hash *h, uint8_t **digest, size_t* len)
{
    uint64_t digest64;
    uint8_t *ret;

    h->methods->final(h->state, &digest64);
    if (!(ret = (uint8_t *)malloc(sizeof(uint64_t)))) return 0;
    U64TO8_LE(ret, digest64);
    *len = sizeof(uint64_t);
    *digest = ret;

    return 1;
}

int
sip_hash_final_integer(sip_hash *h, uint64_t *digest)
{
    h->methods->final(h->state, digest);
    return 1;
}

int
sip_hash_digest(sip_hash *h, uint8_t *data, size_t data_len, uint8_t **digest, size_t *digest_len)
{
    if (!sip_hash_update(h, data, data_len)) return 0;
    return sip_hash_final(h, digest, digest_len);
}

int
sip_hash_digest_integer(sip_hash *h, uint8_t *data, size_t data_len, uint64_t *digest)
{
    if (!sip_hash_update(h, data, data_len)) return 0;
    return sip_hash_final_integer(h, digest);
}

void
sip_hash_free(sip_hash *h)
{
    free(h->state);
    free(h);
}

void
sip_hash_dump(sip_hash *h)
{
    int_sip_dump(h->state);
}

#define SIP_2_ROUND(m, v0, v1, v2, v3)	\
do {					\
    (v3) ^= (m);			\
    SIP_COMPRESS(v0, v1, v2, v3);	\
    SIP_COMPRESS(v0, v1, v2, v3);	\
    (v0) ^= (m);			\
} while (0)

uint64_t
sip_hash24(uint8_t key[16], uint8_t *data, size_t len)
{
    uint64_t k0, k1;
    uint64_t v0, v1, v2, v3;
    uint64_t m, last;
    uint8_t *end = data + len - (len % sizeof(uint64_t));

    k0 = U8TO64_LE(key);
    k1 = U8TO64_LE(key + sizeof(uint64_t));

    v0 = k0 ^ sip_init_state[0];
    v1 = k1 ^ sip_init_state[1];
    v2 = k0 ^ sip_init_state[2];
    v3 = k1 ^ sip_init_state[3];

#if BYTE_ORDER == LITTLE_ENDIAN && UNALIGNED_WORD_ACCESS
    {
        uint64_t *data64 = (uint64_t *)data;
        while (data64 != (uint64_t *) end) {
	    m = *data64++;
	    SIP_2_ROUND(m, v0, v1, v2, v3);
        }
    }
#elif BYTE_ORDER == BIG_ENDIAN
    for (; data != end; data += sizeof(uint64_t)) {
	m = U8TO64_LE(data);
	SIP_2_ROUND(m, v0, v1, v2, v3);
    }
#else
  #error "Only strictly little or big endian supported"
#endif

    last = len << 56;

    switch (len % sizeof(uint64_t)) {
	case 7:
	    last |= ((uint64_t) end[6]) << 48;
	case 6:
	    last |= ((uint64_t) end[5]) << 40;
	case 5:
	    last |= ((uint64_t) end[4]) << 32;
	case 4:
#if BYTE_ORDER == LITTLE_ENDIAN && UNALIGNED_WORD_ACCESS
	    last |= (uint64_t) ((uint32_t *) end)[0];
	    break;
#elif BYTE_ORDER == BIG_ENDIAN
            last |= ((uint64_t) end[3]) << 24;
#else
  #error "Only strictly little or big endian supported"
#endif
	case 3:
	    last |= ((uint64_t) end[2]) << 16;
	case 2:
	    last |= ((uint64_t) end[1]) << 8;
	case 1:
	    last |= (uint64_t) end[0];
	    break;
	case 0:
	    break;
    }

    SIP_2_ROUND(last, v0, v1, v2, v3);

    v2 ^= 0xff;

    SIP_COMPRESS(v0, v1, v2, v3);
    SIP_COMPRESS(v0, v1, v2, v3);
    SIP_COMPRESS(v0, v1, v2, v3);
    SIP_COMPRESS(v0, v1, v2, v3);

    return v0 ^ v1 ^ v2 ^ v3;
}
