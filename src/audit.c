/* audit.c - tamper-evident, hash-chained command audit log.
 *
 * Every command line the shell runs is appended as one record:
 *
 *   seq  time  uid  status  cwd  cmd  alg  prev  mac      (tab-separated)
 *
 * mac = SHA-256 over the first eight fields (alg "h"), or HMAC-SHA256 keyed
 * with $VIGIL_AUDIT_KEY (alg "m"). Because each record includes the previous
 * record's mac, editing, deleting or reordering any record breaks every
 * record after it, and `audit verify` points at the first broken one.
 *
 * Threat model and limits are documented in README.md.
 */
#include "shell.h"
#include "sha256.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define NFIELDS 9
#define GENESIS "0000000000000000000000000000000000000000000000000000000000000000"

static int g_enabled = 0;
static char *g_path = NULL;
static char *g_key = NULL;
static size_t g_keylen = 0;

void audit_init(void) {
    const char *mode = getenv("VIGIL_AUDIT");
    if (mode && strcmp(mode, "off") == 0) return;

    const char *p = getenv("VIGIL_AUDIT_FILE");
    if (p && *p) {
        g_path = xstrdup(p);
    } else {
        const char *home = getenv("HOME");
        if (!home) return;
        size_t n = strlen(home) + 16;
        g_path = xmalloc(n);
        snprintf(g_path, n, "%s/.vigil_audit", home);
    }

    const char *k = getenv("VIGIL_AUDIT_KEY");
    if (k && *k) {
        g_key = xstrdup(k);
        g_keylen = strlen(k);
        /* Do not leak the key to every program the shell runs. */
        unsetenv("VIGIL_AUDIT_KEY");
    }
    g_enabled = 1;
}

/* ---------- encoding ---------- */

static char *encode(const char *s) {
    size_t n = 0;
    for (const char *p = s; *p; p++) n += strchr("\t\n\r%", *p) ? 3 : 1;
    char *out = xmalloc(n + 1), *o = out;
    for (const char *p = s; *p; p++) {
        if (strchr("\t\n\r%", *p)) o += snprintf(o, 4, "%%%02X", (unsigned char)*p);
        else *o++ = *p;
    }
    *o = '\0';
    return out;
}

static char *decode(const char *s) {
    char *out = xmalloc(strlen(s) + 1), *o = out;
    for (const char *p = s; *p; p++) {
        unsigned v;
        if (*p == '%' && p[1] && p[2] && sscanf(p + 1, "%2X", &v) == 1) {
            *o++ = (char)v;
            p += 2;
        } else {
            *o++ = *p;
        }
    }
    *o = '\0';
    return out;
}

/* ---------- record helpers ---------- */

static void compute_mac(char alg, const char *body, size_t len, char hex[SHA256_HEX_LEN + 1]) {
    uint8_t d[SHA256_DIGEST_LEN];
    if (alg == 'm') hmac_sha256(g_key, g_keylen, body, len, d);
    else sha256(body, len, d);
    sha256_to_hex(d, hex);
}

/* Splits a line in place into exactly NFIELDS tab-separated fields. */
static int split(char *line, char *f[NFIELDS]) {
    int n = 0;
    char *p = line;
    f[n++] = p;
    for (; *p; p++) {
        if (*p == '\t') {
            *p = '\0';
            if (n == NFIELDS) return -1;
            f[n++] = p + 1;
        }
    }
    return n == NFIELDS ? 0 : -1;
}

static char *read_all(int fd, size_t *len) {
    size_t cap = 4096, n = 0;
    char *buf = xmalloc(cap + 1);
    if (lseek(fd, 0, SEEK_SET) < 0) { free(buf); return NULL; }
    for (;;) {
        if (n == cap) { cap *= 2; buf = xrealloc(buf, cap + 1); }
        ssize_t r = read(fd, buf + n, cap - n);
        if (r < 0) { if (errno == EINTR) continue; free(buf); return NULL; }
        if (r == 0) break;
        n += (size_t)r;
    }
    buf[n] = '\0';
    *len = n;
    return buf;
}

static int open_log(int flags) {
    flags |= O_NOFOLLOW;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    int fd = open(g_path, flags, 0600);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        errno = EINVAL;
        return -1;
    }
    return fd;
}

void audit_record(const char *cmdline, int status) {
    if (!g_enabled) return;
    int fd = open_log(O_RDWR | O_CREAT | O_APPEND);
    if (fd < 0) {
        static int warned = 0;
        if (!warned++) fprintf(stderr, "vigil: audit: cannot open %s: %s\n", g_path, strerror(errno));
        return;
    }
    if (flock(fd, LOCK_EX) != 0) { close(fd); return; }

    /* Find the last record to chain from (under the lock, so concurrent
     * shells writing the same log still form one chain). */
    size_t len = 0;
    char *all = read_all(fd, &len);
    unsigned long long seq = 1;
    char prev[SHA256_HEX_LEN + 1] = GENESIS;
    if (all && len > 0) {
        char *end = all + len;
        while (end > all && end[-1] == '\n') *--end = '\0';
        char *last = strrchr(all, '\n');
        last = last ? last + 1 : all;
        unsigned long long lines = 1;
        for (char *q = all; q < last; q++) lines += *q == '\n';
        char *f[NFIELDS];
        if (*last && split(last, f) == 0 && strlen(f[8]) == SHA256_HEX_LEN) {
            seq = strtoull(f[0], NULL, 10) + 1;
            memcpy(prev, f[8], SHA256_HEX_LEN + 1);
        } else if (*last) {
            /* Damaged tail: keep appending, verify will report it. */
            uint8_t d[SHA256_DIGEST_LEN];
            sha256(last, strlen(last), d);
            sha256_to_hex(d, prev);
            seq = lines + 1;
        }
    }
    free(all);

    char cwd[4096];
    if (!getcwd(cwd, sizeof cwd)) strcpy(cwd, "?");
    char *ecwd = encode(cwd), *ecmd = encode(cmdline);
    char alg = g_key ? 'm' : 'h';

    size_t bodycap = strlen(ecwd) + strlen(ecmd) + 256;
    char *body = xmalloc(bodycap);
    int blen = snprintf(body, bodycap, "%llu\t%lld\t%ld\t%d\t%s\t%s\t%c\t%s", seq,
                        (long long)time(NULL), (long)getuid(), status, ecwd, ecmd, alg, prev);
    char mac[SHA256_HEX_LEN + 1];
    compute_mac(alg, body, (size_t)blen, mac);

    size_t reccap = (size_t)blen + SHA256_HEX_LEN + 3;
    char *rec = xmalloc(reccap);
    int rlen = snprintf(rec, reccap, "%s\t%s\n", body, mac);
    if (write(fd, rec, (size_t)rlen) != rlen)
        fprintf(stderr, "vigil: audit: write failed: %s\n", strerror(errno));

    free(rec);
    free(body);
    free(ecwd);
    free(ecmd);
    flock(fd, LOCK_UN);
    close(fd);
}

/* ---------- the `audit` builtin ---------- */

static int audit_verify(const char *anchor) {
    int fd = open_log(O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "audit: cannot open %s: %s\n", g_path, strerror(errno));
        return 2;
    }
    flock(fd, LOCK_SH);
    size_t len;
    char *all = read_all(fd, &len);
    flock(fd, LOCK_UN);
    close(fd);
    if (!all) { perror("audit: read"); return 2; }

    char prev[SHA256_HEX_LEN + 1] = GENESIS;
    unsigned long long expect = 1, n = 0;
    int anchor_found = 0, rc = 0;
    long lineno = 0;
    char *save = all;

    for (char *line = all; line && *line;) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        lineno++;
        if (*line == '\0') { line = nl ? nl + 1 : NULL; continue; }

        char *f[NFIELDS];
        const char *why = NULL;
        if (split(line, f) != 0) {
            why = "malformed record";
        } else if (strtoull(f[0], NULL, 10) != expect) {
            why = "sequence number out of order (record inserted or deleted)";
        } else if (strcmp(f[7], prev) != 0) {
            why = "chain link broken (previous record changed or removed)";
        } else if (f[6][0] == 'm' && !g_key) {
            fprintf(stderr, "audit: record %llu is HMAC-protected; set VIGIL_AUDIT_KEY to verify\n", expect);
            rc = 2;
            break;
        } else if (f[6][0] == 'h' && g_key) {
            why = "unkeyed record in a keyed log (possible downgrade/forgery)";
        } else if (f[6][1] != '\0' || (f[6][0] != 'h' && f[6][0] != 'm')) {
            why = "unknown algorithm";
        } else {
            /* Recompute over the original bytes: re-join fields 0..7. */
            size_t blen = 0;
            for (int i = 0; i < 8; i++) blen += strlen(f[i]) + 1;
            char *body = xmalloc(blen);
            body[0] = '\0';
            for (int i = 0; i < 8; i++) {
                if (i) strcat(body, "\t");
                strcat(body, f[i]);
            }
            char mac[SHA256_HEX_LEN + 1];
            compute_mac(f[6][0], body, strlen(body), mac);
            free(body);
            if (strlen(f[8]) != SHA256_HEX_LEN || !ct_equal(mac, f[8], SHA256_HEX_LEN))
                why = "hash mismatch (record contents were modified)";
        }

        if (why) {
            fprintf(stderr, "audit: TAMPERED at line %ld (expected record %llu): %s\n", lineno, expect, why);
            rc = 1;
            break;
        }
        if (anchor && strcmp(anchor, f[8]) == 0) anchor_found = 1;
        memcpy(prev, f[8], SHA256_HEX_LEN + 1);
        expect++;
        n++;
        line = nl ? nl + 1 : NULL;
    }
    free(save);

    if (rc == 0 && anchor && !anchor_found) {
        fprintf(stderr, "audit: TAMPERED: anchor %s not found (log truncated or rewritten)\n", anchor);
        rc = 1;
    }
    if (rc == 0) printf("audit: OK  %llu records, chain intact\nhead: %s\n", n, prev);
    return rc;
}

static int audit_tail(int count) {
    int fd = open_log(O_RDONLY);
    if (fd < 0) { fprintf(stderr, "audit: cannot open %s: %s\n", g_path, strerror(errno)); return 2; }
    size_t len;
    char *all = read_all(fd, &len);
    close(fd);
    if (!all) return 2;

    /* collect line starts */
    size_t nlines = 0, cap = 64;
    char **lines = xmalloc(sizeof(char *) * cap);
    for (char *p = strtok(all, "\n"); p; p = strtok(NULL, "\n")) {
        if (nlines == cap) { cap *= 2; lines = xrealloc(lines, sizeof(char *) * cap); }
        lines[nlines++] = p;
    }
    size_t start = nlines > (size_t)count ? nlines - (size_t)count : 0;
    for (size_t i = start; i < nlines; i++) {
        char *f[NFIELDS];
        if (split(lines[i], f) != 0) { printf("?      (malformed record)\n"); continue; }
        time_t t = (time_t)strtoll(f[1], NULL, 10);
        char ts[32];
        strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", localtime(&t));
        char *cmd = decode(f[5]);
        printf("%-6s %s  [%3s]  %s\n", f[0], ts, f[3], cmd);
        free(cmd);
    }
    free(lines);
    free(all);
    return 0;
}

int builtin_audit(int argc, char **argv) {
    if (!g_enabled) {
        fprintf(stderr, "audit: logging is disabled (VIGIL_AUDIT=off or --no-audit)\n");
        return 2;
    }
    const char *sub = argc > 1 ? argv[1] : "tail";
    if (strcmp(sub, "verify") == 0) {
        const char *anchor = NULL;
        if (argc > 2) {
            if (strcmp(argv[2], "--anchor") == 0 && argc > 3) anchor = argv[3];
            else { fprintf(stderr, "usage: audit verify [--anchor HASH]\n"); return 2; }
        }
        return audit_verify(anchor);
    }
    if (strcmp(sub, "tail") == 0) {
        int n = argc > 2 ? atoi(argv[2]) : 10;
        return audit_tail(n > 0 ? n : 10);
    }
    if (strcmp(sub, "head") == 0) {
        int fd = open_log(O_RDONLY);
        if (fd < 0) { printf("%s\n", GENESIS); return 0; }
        size_t len;
        char *all = read_all(fd, &len);
        close(fd);
        if (!all) return 2;
        char *last = NULL;
        for (char *p = strtok(all, "\n"); p; p = strtok(NULL, "\n")) last = p;
        char *f[NFIELDS];
        if (last && split(last, f) == 0) printf("%s\n", f[8]);
        else printf("%s\n", GENESIS);
        free(all);
        return 0;
    }
    if (strcmp(sub, "path") == 0) {
        printf("%s\n", g_path);
        return 0;
    }
    fprintf(stderr, "usage: audit [tail [N] | verify [--anchor HASH] | head | path]\n");
    return 2;
}

void audit_disable(void) { g_enabled = 0; }
