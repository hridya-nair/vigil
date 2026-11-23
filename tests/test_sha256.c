/* Known-answer tests for SHA-256 (FIPS 180-4 examples) and HMAC-SHA256 (RFC 4231). */
#include "sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

static void check(const char *name, const uint8_t d[32], const char *want) {
    char hex[65];
    sha256_to_hex(d, hex);
    if (strcmp(hex, want) != 0) {
        printf("FAIL %s\n  got  %s\n  want %s\n", name, hex, want);
        failures++;
    } else {
        printf("ok   %s\n", name);
    }
}

int main(void) {
    uint8_t d[32];

    sha256("", 0, d);
    check("sha256 empty", d, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    sha256("abc", 3, d);
    check("sha256 abc", d, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    const char *m448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha256(m448, strlen(m448), d);
    check("sha256 448-bit", d, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    /* one million 'a', fed in uneven chunks to exercise buffering */
    sha256_ctx c;
    sha256_init(&c);
    char chunk[997];
    memset(chunk, 'a', sizeof chunk);
    size_t left = 1000000;
    while (left) {
        size_t n = left < sizeof chunk ? left : sizeof chunk;
        sha256_update(&c, chunk, n);
        left -= n;
    }
    sha256_final(&c, d);
    check("sha256 million a", d, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

    /* RFC 4231 test case 1 */
    uint8_t key1[20];
    memset(key1, 0x0b, sizeof key1);
    hmac_sha256(key1, sizeof key1, "Hi There", 8, d);
    check("hmac rfc4231 #1", d, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    /* RFC 4231 test case 2 */
    const char *msg2 = "what do ya want for nothing?";
    hmac_sha256("Jefe", 4, msg2, strlen(msg2), d);
    check("hmac rfc4231 #2", d, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

    /* RFC 4231 test case 6: key longer than the block size */
    uint8_t key6[131];
    memset(key6, 0xaa, sizeof key6);
    const char *msg6 = "Test Using Larger Than Block-Size Key - Hash Key First";
    hmac_sha256(key6, sizeof key6, msg6, strlen(msg6), d);
    check("hmac rfc4231 #6", d, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

    printf("%s\n", failures ? "SHA-256 TESTS FAILED" : "all SHA-256 tests passed");
    return failures ? 1 : 0;
}
