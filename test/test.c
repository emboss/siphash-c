#include "siphash.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static uint8_t SPEC_KEY[16] = {
   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
   0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};	

static uint8_t SPEC_MSG[15] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e
};

static void 
test_spec_streaming(void)
{
    uint64_t digest64;
    sip_hash *h;
   
    assert(h = sip_hash_new(SPEC_KEY, 2, 4));
    assert(sip_hash_update(h, SPEC_MSG, 15));
    assert(sip_hash_final_integer(h, &digest64));

    sip_hash_free(h);

    assert(digest64 == 0xa129ca6149be45e5ULL);
}

static void
test_spec_one_pass(void)
{
    uint64_t digest64;
    sip_hash *h;
   
    assert(h = sip_hash_new(SPEC_KEY, 2, 4));
    assert(sip_hash_digest_integer(h, SPEC_MSG, 15, &digest64));

    sip_hash_free(h);

    printf("Spec: %" PRIx64 "\n", digest64); 
    assert(digest64 == 0xa129ca6149be45e5ULL);
}

static void
test_empty_string(void)
{
    uint64_t digest64;
    sip_hash *h;

    assert(h = sip_hash_new(SPEC_KEY, 2, 4));
    assert(sip_hash_digest_integer(h, (uint8_t *) "", 0, &digest64));
    printf("Empty string : %" PRIx64 "\n", digest64); 

    sip_hash_free(h);
}

static void
test_one_byte(void)
{
    uint64_t digest64;
    sip_hash *h;

    assert(h = sip_hash_new(SPEC_KEY, 2, 4));
    assert(sip_hash_digest_integer(h, (uint8_t *) "a", 1, &digest64));
    printf("One byte (a): %" PRIx64 "\n", digest64); 

    sip_hash_free(h);
}

static void
test_six_bytes(void)
{
    uint64_t digest64;
    sip_hash *h;

    assert(h = sip_hash_new(SPEC_KEY, 2, 4));
    assert(sip_hash_digest_integer(h, (uint8_t *) "abcdef", 6, &digest64));
    printf("Six bytes (abcdef): %" PRIx64 "\n", digest64); 

    sip_hash_free(h);
}

static void
test_seven_bytes(void)
{
    uint64_t digest64;
    sip_hash *h;

    assert(h = sip_hash_new(SPEC_KEY, 2, 4));
    assert(sip_hash_digest_integer(h, (uint8_t *) "SipHash", 7, &digest64));
    printf("Seven bytes (SipHash): %" PRIx64 "\n", digest64); 

    sip_hash_free(h);
}

static void
test_eight_bytes(void)
{
    uint64_t digest64;
    sip_hash *h;

    assert(h = sip_hash_new(SPEC_KEY, 2, 4));
    assert(sip_hash_digest_integer(h, (uint8_t *) "12345678", 8, &digest64));
    printf("Eight bytes (12345678): %" PRIx64 "\n", digest64); 

    sip_hash_free(h);
}

static void
test_one_mio_zero_bytes(void)
{
    uint64_t digest64;
    uint8_t msg[1000000];
    sip_hash *h;

    memset(msg, 0, 1000000);
    assert(h = sip_hash_new(SPEC_KEY, 2, 4));
    assert(sip_hash_digest_integer(h, msg, 1000000, &digest64));
    printf("One million zero bytes: %" PRIx64 "\n", digest64); 

    sip_hash_free(h);
}

static void
test_24_spec(void)
{
    uint64_t digest64;
   
    digest64 = sip_hash24(SPEC_KEY, SPEC_MSG, 15);
    printf("sip_hash24 spec: %" PRIx64 "\n", digest64); 
    assert(digest64 == 0xa129ca6149be45e5ULL);
}

static void
test_24_empty_string(void)
{
    uint64_t digest64;
   
    digest64 = sip_hash24(SPEC_KEY, (uint8_t *) "", 0);
    printf("sip_hash24 empty string: %" PRIx64 "\n", digest64); 
}

static void
test_24_one_byte(void)
{
    uint64_t digest64;
   
    digest64 = sip_hash24(SPEC_KEY, (uint8_t *) "a", 1);
    printf("sip_hash24 one byte (a): %" PRIx64 "\n", digest64); 
}

static void
test_24_six_bytes(void)
{
    uint64_t digest64;
   
    digest64 = sip_hash24(SPEC_KEY, (uint8_t *) "abcdef", 6);
    printf("sip_hash24 six bytes (a): %" PRIx64 "\n", digest64); 
}

static void
test_24_seven_bytes(void)
{
    uint64_t digest64;
   
    digest64 = sip_hash24(SPEC_KEY, (uint8_t *) "SipHash", 7);
    printf("sip_hash24 seven bytes (SipHash): %" PRIx64 "\n", digest64); 
}

static void
test_24_eight_bytes(void)
{
    uint64_t digest64;
   
    digest64 = sip_hash24(SPEC_KEY, (uint8_t *) "12345678", 8);
    printf("sip_hash24 eight bytes (12345678): %" PRIx64 "\n", digest64); 
}

static void
test_24_one_mio_zero_bytes(void)
{
    uint64_t digest64;
    uint8_t msg[1000000];

    memset(msg, 0, 1000000);
    digest64 = sip_hash24(SPEC_KEY, msg, 1000000);
    printf("sip_hash24 one million zero bytes: %" PRIx64 "\n", digest64); 
}

int main(int argc, char **argv) {
    test_spec_streaming();
    test_spec_one_pass();

    test_empty_string();
    test_one_byte();
    test_six_bytes();
    test_seven_bytes();
    test_eight_bytes();
    //test_fifteen_bytes(); tested by the spec
    test_one_mio_zero_bytes();

    test_24_spec();

    test_24_empty_string();
    test_24_one_byte();
    test_24_six_bytes();
    test_24_seven_bytes();
    test_24_eight_bytes();
    //test_24_fifteen_bytes(); tested by the spec
    test_24_one_mio_zero_bytes();

    return EXIT_SUCCESS;
}
