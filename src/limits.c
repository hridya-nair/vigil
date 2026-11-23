/* limits.c - the `limit` prefix: run one command under resource limits.
 *
 *   limit cpu=2 mem=256M fsize=10M files=32 nproc=64 -- ./untrusted arg
 *
 * Limits are applied with setrlimit() in the child after fork() and before
 * exec(), so they only affect that command (and anything it spawns), never
 * the shell itself.
 */
#include "shell.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

/* Parses "123", "64K", "256M", "2G". */
static int parse_size(const char *s, unsigned long long *out) {
    char *end;
    errno = 0;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno || end == s || s[0] == '-') return -1;
    unsigned long long mult = 1;
    if (*end) {
        switch (*end) {
        case 'k': case 'K': mult = 1024ULL; break;
        case 'm': case 'M': mult = 1024ULL * 1024; break;
        case 'g': case 'G': mult = 1024ULL * 1024 * 1024; break;
        default: return -1;
        }
        if (end[1] != '\0') return -1;
    }
    if (v > ~0ULL / mult) return -1;
    *out = v * mult;
    return 0;
}

int limits_parse(char **argv, limits *l) {
    memset(l, 0, sizeof *l);
    int i = 1;
    for (; argv[i]; i++) {
        if (strcmp(argv[i], "--") == 0) { i++; break; }
        char *eq = strchr(argv[i], '=');
        if (!eq) break; /* first non k=v word starts the command */
        size_t klen = (size_t)(eq - argv[i]);
        const char *val = eq + 1;
        unsigned long long v;
        int is_size = (klen == 3 && strncmp(argv[i], "mem", 3) == 0) ||
                      (klen == 5 && strncmp(argv[i], "fsize", 5) == 0);
        if (parse_size(val, &v) != 0 || (!is_size && strpbrk(val, "kKmMgG"))) {
            fprintf(stderr, "vigil: limit: bad value '%s'\n", argv[i]);
            return -1;
        }
        if (klen == 3 && strncmp(argv[i], "cpu", 3) == 0) { l->set_cpu = 1; l->cpu = v; }
        else if (klen == 3 && strncmp(argv[i], "mem", 3) == 0) { l->set_mem = 1; l->mem = v; }
        else if (klen == 5 && strncmp(argv[i], "fsize", 5) == 0) { l->set_fsize = 1; l->fsize = v; }
        else if (klen == 5 && strncmp(argv[i], "files", 5) == 0) { l->set_files = 1; l->files = v; }
        else if (klen == 5 && strncmp(argv[i], "nproc", 5) == 0) { l->set_nproc = 1; l->nproc = v; }
        else {
            fprintf(stderr, "vigil: limit: unknown resource '%.*s' "
                            "(use cpu, mem, fsize, files, nproc)\n", (int)klen, argv[i]);
            return -1;
        }
    }
    if (!argv[i]) {
        fprintf(stderr, "vigil: limit: missing command\n"
                        "usage: limit [cpu=SEC] [mem=SIZE] [fsize=SIZE] [files=N] [nproc=N] [--] cmd [args]\n");
        return -1;
    }
    return i;
}

static int set_one(int resource, unsigned long long v, const char *name) {
    struct rlimit rl;
    if (getrlimit(resource, &rl) != 0) rl.rlim_max = RLIM_INFINITY;
    rlim_t want = (rlim_t)v;
    /* Can only lower the hard limit, never raise it. */
    if (rl.rlim_max != RLIM_INFINITY && want > rl.rlim_max) want = rl.rlim_max;
    rl.rlim_cur = want;
    rl.rlim_max = want;
    if (setrlimit(resource, &rl) != 0) {
        fprintf(stderr, "vigil: limit: cannot set %s: %s\n", name, strerror(errno));
        return -1;
    }
    return 0;
}

int limits_apply(const limits *l) {
    if (l->set_cpu) {
        /* soft limit sends SIGXCPU; hard limit one second later sends SIGKILL */
        struct rlimit rl;
        rl.rlim_cur = (rlim_t)l->cpu;
        rl.rlim_max = (rlim_t)l->cpu + 1;
        if (setrlimit(RLIMIT_CPU, &rl) != 0) {
            fprintf(stderr, "vigil: limit: cannot set cpu: %s\n", strerror(errno));
            return -1;
        }
    }
    if (l->set_mem) {
        /* Linux enforces RLIMIT_AS. macOS accepts it but does not enforce it. */
        if (set_one(RLIMIT_AS, l->mem, "mem") != 0) return -1;
    }
    if (l->set_fsize && set_one(RLIMIT_FSIZE, l->fsize, "fsize") != 0) return -1;
    if (l->set_files && set_one(RLIMIT_NOFILE, l->files, "files") != 0) return -1;
#ifdef RLIMIT_NPROC
    if (l->set_nproc && set_one(RLIMIT_NPROC, l->nproc, "nproc") != 0) return -1;
#endif
    return 0;
}

static void show(const char *name, int res, const char *unit) {
    struct rlimit rl;
    if (getrlimit(res, &rl) != 0) return;
    if (rl.rlim_cur == RLIM_INFINITY) printf("%-6s unlimited\n", name);
    else printf("%-6s %llu%s\n", name, (unsigned long long)rl.rlim_cur, unit);
}

void limits_print_current(void) {
    show("cpu", RLIMIT_CPU, " s");
    show("mem", RLIMIT_AS, " bytes");
    show("fsize", RLIMIT_FSIZE, " bytes");
    show("files", RLIMIT_NOFILE, "");
#ifdef RLIMIT_NPROC
    show("nproc", RLIMIT_NPROC, "");
#endif
}
