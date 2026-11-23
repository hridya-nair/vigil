/* util.c - allocation helpers and global state shared by every module. */
#include "shell.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

shell_state g_shell;

void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) { perror("vigil: malloc"); exit(1); }
    return p;
}

void *xrealloc(void *p, size_t n) {
    void *q = realloc(p, n ? n : 1);
    if (!q) { perror("vigil: realloc"); exit(1); }
    return q;
}

char *xstrdup(const char *s) {
    size_t n = strlen(s) + 1;
    char *d = xmalloc(n);
    memcpy(d, s, n);
    return d;
}
