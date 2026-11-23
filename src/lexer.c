/* lexer.c - turns an input line into tokens.
 *
 * Handles:  'single quotes'  "double quotes"  \escapes  # comments
 *           $VAR ${VAR} $? $$  ~ and ~/path
 *           | || & && ; < > >> 2> 2>> 2>&1
 *
 * Words keep their raw text here; expand_word() runs at execution time,
 * so `export X=1; echo $X` works on one line. Expanded values are NEVER
 * re-split into multiple words or glob-expanded. A variable containing "a; rm -rf ~"
 * stays one literal argument. That closes off the classic word-splitting
 * injection bugs from POSIX shells.
 */
#include "shell.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    char *s;
    size_t len, cap;
} strbuf;

static void sb_putc(strbuf *b, char c) {
    if (b->len + 2 > b->cap) {
        b->cap = b->cap ? b->cap * 2 : 32;
        b->s = xrealloc(b->s, b->cap);
    }
    b->s[b->len++] = c;
    b->s[b->len] = '\0';
}

static void sb_puts(strbuf *b, const char *s) {
    while (*s) sb_putc(b, *s++);
}

static void push(token_list *tl, token_type t, char *text) {
    if (tl->len == tl->cap) {
        tl->cap = tl->cap ? tl->cap * 2 : 16;
        tl->items = xrealloc(tl->items, tl->cap * sizeof *tl->items);
    }
    tl->items[tl->len].type = t;
    tl->items[tl->len].text = text;
    tl->len++;
}

void token_list_free(token_list *tl) {
    for (size_t i = 0; i < tl->len; i++) free(tl->items[i].text);
    free(tl->items);
    tl->items = NULL;
    tl->len = tl->cap = 0;
}

static int is_name_start(char c) { return isalpha((unsigned char)c) || c == '_'; }
static int is_name_char(char c) { return isalnum((unsigned char)c) || c == '_'; }

/* Expands a $... reference starting at p (which points just past '$').
 * Appends the value to b and returns the number of input chars consumed. */
static size_t expand_dollar(const char *p, strbuf *b, const char **err) {
    char num[32];
    if (*p == '?') {
        snprintf(num, sizeof num, "%d", g_shell.last_status);
        sb_puts(b, num);
        return 1;
    }
    if (*p == '$') {
        snprintf(num, sizeof num, "%ld", (long)getpid());
        sb_puts(b, num);
        return 1;
    }
    if (*p == '{') {
        const char *end = strchr(p + 1, '}');
        if (!end) {
            *err = "missing '}' in ${...}";
            return 0;
        }
        size_t n = (size_t)(end - p - 1);
        if (n == 0 || !is_name_start(p[1])) {
            *err = "bad substitution";
            return 0;
        }
        for (size_t i = 1; i < n; i++)
            if (!is_name_char(p[1 + i])) {
                *err = "bad substitution";
                return 0;
            }
        char *name = xmalloc(n + 1);
        memcpy(name, p + 1, n);
        name[n] = '\0';
        const char *v = getenv(name);
        if (v) sb_puts(b, v);
        free(name);
        return n + 2;
    }
    if (is_name_start(*p)) {
        size_t n = 1;
        while (is_name_char(p[n])) n++;
        char *name = xmalloc(n + 1);
        memcpy(name, p, n);
        name[n] = '\0';
        const char *v = getenv(name);
        if (v) sb_puts(b, v);
        free(name);
        return n;
    }
    /* A lone '$' is literal. */
    sb_putc(b, '$');
    return 0;
}

/* Scans one word starting at *pp. With expand=0 it only validates and
 * advances (used while tokenizing); with expand=1 it produces the final
 * argument text (used at execution time). Returns 0 or -1 on error. */
static int scan_word(const char **pp, strbuf *b, int expand, int *quoted, const char **err) {
    const char *p = *pp;
    *quoted = 0;

    if (*p == '~' && (p[1] == '\0' || p[1] == '/' || strchr(" \t\n;|&<>", p[1]))) {
        if (expand) {
            const char *home = getenv("HOME");
            sb_puts(b, home ? home : "~");
        }
        p++;
    }

    while (*p && !strchr(" \t\n\r;|&<>", *p)) {
        if (*p == '\\') {
            if (p[1] == '\0') { p++; break; }
            if (expand) sb_putc(b, p[1]);
            p += 2;
        } else if (*p == '\'') {
            *quoted = 1;
            const char *end = strchr(p + 1, '\'');
            if (!end) { *err = "unterminated single quote"; return -1; }
            if (expand)
                for (const char *q = p + 1; q < end; q++) sb_putc(b, *q);
            p = end + 1;
        } else if (*p == '"') {
            *quoted = 1;
            p++;
            while (*p && *p != '"') {
                if (*p == '\\' && p[1] && strchr("\"\\$", p[1])) {
                    if (expand) sb_putc(b, p[1]);
                    p += 2;
                } else if (*p == '$') {
                    strbuf tmp = {0};
                    size_t used = expand_dollar(p + 1, expand ? b : &tmp, err);
                    free(tmp.s);
                    if (*err) return -1;
                    p += 1 + used;
                } else {
                    if (expand) sb_putc(b, *p);
                    p++;
                }
            }
            if (*p != '"') { *err = "unterminated double quote"; return -1; }
            p++;
        } else if (*p == '$') {
            strbuf tmp = {0};
            size_t used = expand_dollar(p + 1, expand ? b : &tmp, err);
            free(tmp.s);
            if (*err) return -1;
            p += 1 + used;
        } else {
            if (expand) sb_putc(b, *p);
            p++;
        }
    }
    *pp = p;
    return 0;
}

char *expand_word(const char *raw, const char **err) {
    strbuf b = {0};
    int quoted;
    const char *p = raw;
    *err = NULL;
    if (scan_word(&p, &b, 1, &quoted, err) != 0) {
        free(b.s);
        return NULL;
    }
    if (b.len == 0 && !quoted) { /* unquoted $EMPTY expands to nothing */
        free(b.s);
        return NULL;
    }
    return b.s ? b.s : xstrdup("");
}

int lex(const char *in, token_list *out, const char **err) {
    out->items = NULL;
    out->len = out->cap = 0;
    *err = NULL;

    const char *p = in;
    while (*p) {
        if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
            p++;
            continue;
        }
        if (*p == '#') break; /* comment to end of line */

        /* operators */
        if (p[0] == '2' && p[1] == '>' && p[2] == '&' && p[3] == '1') {
            push(out, TOK_ERR_TO_OUT, NULL); p += 4; continue;
        }
        if (p[0] == '2' && p[1] == '>' && p[2] == '>') { push(out, TOK_ERR_GTGT, NULL); p += 3; continue; }
        if (p[0] == '2' && p[1] == '>') { push(out, TOK_ERR_GT, NULL); p += 2; continue; }
        if (p[0] == '|' && p[1] == '|') { push(out, TOK_OR, NULL); p += 2; continue; }
        if (p[0] == '&' && p[1] == '&') { push(out, TOK_AND, NULL); p += 2; continue; }
        if (p[0] == '>' && p[1] == '>') { push(out, TOK_GTGT, NULL); p += 2; continue; }
        if (*p == '|') { push(out, TOK_PIPE, NULL); p++; continue; }
        if (*p == '&') { push(out, TOK_AMP, NULL); p++; continue; }
        if (*p == ';') { push(out, TOK_SEMI, NULL); p++; continue; }
        if (*p == '<') { push(out, TOK_LT, NULL); p++; continue; }
        if (*p == '>') { push(out, TOK_GT, NULL); p++; continue; }

        /* A word: keep its raw text; expansion happens when it runs. */
        const char *start = p;
        strbuf unused = {0};
        int quoted;
        if (scan_word(&p, &unused, 0, &quoted, err) != 0) {
            token_list_free(out);
            return -1;
        }
        size_t n = (size_t)(p - start);
        char *raw = xmalloc(n + 1);
        memcpy(raw, start, n);
        raw[n] = '\0';
        push(out, TOK_WORD, raw);
    }
    return 0;
}
