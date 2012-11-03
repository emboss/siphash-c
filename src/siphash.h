#ifndef SIPHASH_H
#define SIPHASH_H 1
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

typedef struct sip_hash_st sip_hash;

sip_hash *sip_hash_new(uint8_t key[16], int c, int d);
int sip_hash_update(sip_hash *h, uint8_t *data, size_t len);
int sip_hash_final(sip_hash *h, uint8_t **digest, size_t *len);
int sip_hash_final_integer(sip_hash *h, uint64_t *digest);
int sip_hash_digest(sip_hash *h, uint8_t *data, size_t data_len, uint8_t **digest, size_t *digest_len);
int sip_hash_digest_integer(sip_hash *h, uint8_t *data, size_t data_len, uint64_t *digest);
void sip_hash_free(sip_hash *h);
void sip_hash_dump(sip_hash *h);

uint64_t sip_hash24(uint8_t key[16], uint8_t *data, uint64_t len);

#endif
