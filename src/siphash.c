#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include "siphash.h"

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

typedef struct sip_state_st {
  int c;
  int d;
  uint64_t v[4];
  uint8_t buf[8];
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

typedef struct sip_hash_st {
    sip_state *state;
    sip_interface *methods;
} sip_hash;

static void int_sip_init(sip_state *state, uint8_t *key);
static void int_sip_update(sip_state *state, uint8_t *data, size_t len);
static void int_sip_final(sip_state *state, uint64_t *digest);

sip_interface sip_methods = {
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
    k1 = U8TO64_LE(key + 8);

    state->v[0] = k0 ^ sip_init_state[0];
    state->v[1] = k1 ^ sip_init_state[1];
    state->v[2] = k0 ^ sip_init_state[2];
    state->v[3] = k1 ^ sip_init_state[3];
}

static void
int_sip_round(sip_state *state, int n)
{
    int i;

    for (i = 0; i < n; i++) {
	SIP_COMPRESS(state->v[0], state->v[1], state->v[2], state->v[3]);
    }
}

static void
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

    to_read = 8 - state->buflen;
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
    uint8_t r = len % 8;
    if (r) {
	memcpy(state->buf, data + len - r, r);
	state->buflen = r;
    }
}

static void 
int_sip_update(sip_state *state, uint8_t *data, size_t len)
{
    uint64_t m;
    size_t i;
   
    state->msglen_byte = state->msglen_byte + (len % 256);

    int_sip_pre_update(state, &data, &len);

    for (i = 0; i < len / 8; i++) {
	m = U8TO64_LE(data + (i * 8));
	int_sip_update_block(state, m);
    }

    int_sip_post_update(state, data, len);
}

static inline void
int_sip_pad_final_block(sip_state *state)
{
    int i;
    //pad with 0's and finalize with msg_len mod 256
    for (i = state->buflen; i < 7; i++) {
	state->buf[i] = 0x00;
    }
    state->buf[7] = state->msglen_byte;
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
    sip_hash *h;

    if (!(h = (sip_hash *) malloc(sizeof(sip_hash)))) return NULL;
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
    uint64_t last;
    uint64_t *data64 = (uint64_t *)data;
    uint64_t *end;

    k0 = U8TO64_LE(key);
    k1 = U8TO64_LE(key + 8);

    v0 = k0 ^ sip_init_state[0];
    v1 = k1 ^ sip_init_state[1];
    v2 = k0 ^ sip_init_state[2];
    v3 = k1 ^ sip_init_state[3];

    end = data64 + (len / 8);

    while (data64 != end) {
	uint64_t m = *data64;

	SIP_2_ROUND(m, v0, v1, v2, v3);
	data64++;
    }

    last = ((uint64_t) len) << 56;

    switch (len % 8) {
	case 7: 
	    last |= ((uint64_t) ((uint8_t *) end)[6]) << 48;
	case 6:
	    last |= ((uint64_t) ((uint8_t *) end)[5]) << 40;
	case 5:
	    last |= ((uint64_t) ((uint8_t *) end)[4]) << 32;
	case 4:
	    last |= (uint64_t) ((uint32_t *) end)[0];
	    break;
	case 3:
	    last |= ((uint64_t) ((uint8_t *)end)[2]) << 16;
	case 2:
	    last |= ((uint64_t) ((uint8_t *)end)[1]) << 8;
	case 1:
	    last |= (uint64_t) ((uint8_t *)end)[0];
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
