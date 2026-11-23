/* parser.c - builds a command list from tokens.
 *
 * Grammar:
 *   list      := item ( (';' | '&' | '&&' | '||') item )* [';' | '&']
 *   item      := pipeline
 *   pipeline  := command ( '|' command )*
 *   command   := ( WORD | redirect )+
 *   redirect  := ('<' | '>' | '>>' | '2>' | '2>>') WORD | '2>&1'
 */
#include "shell.h"

#include <stdlib.h>
#include <string.h>

static void command_free(command *c) {
    for (int i = 0; i < c->argc; i++) free(c->argv[i]);
    free(c->argv);
    free(c->in_file);
    free(c->out_file);
    free(c->err_file);
}

void command_list_free(command_list *cl) {
    for (int i = 0; i < cl->nitems; i++) {
        pipeline *pl = &cl->items[i].pl;
        for (int j = 0; j < pl->ncmds; j++) command_free(&pl->cmds[j]);
        free(pl->cmds);
    }
    free(cl->items);
    cl->items = NULL;
    cl->nitems = 0;
}

static int is_redirect(token_type t) {
    return t == TOK_LT || t == TOK_GT || t == TOK_GTGT || t == TOK_ERR_GT ||
           t == TOK_ERR_GTGT || t == TOK_ERR_TO_OUT;
}

static void set_file(char **slot, const char *name) {
    free(*slot);
    *slot = xstrdup(name);
}

/* Parses one command starting at *i. Returns 0 on success. */
static int parse_command(const token_list *tl, size_t *i, command *c, const char **err) {
    memset(c, 0, sizeof *c);
    int cap = 4;
    c->argv = xmalloc(sizeof(char *) * (size_t)cap);

    while (*i < tl->len) {
        const token *t = &tl->items[*i];
        if (t->type == TOK_WORD) {
            if (c->argc + 1 >= cap) {
                cap *= 2;
                c->argv = xrealloc(c->argv, sizeof(char *) * (size_t)cap);
            }
            c->argv[c->argc++] = xstrdup(t->text);
            (*i)++;
        } else if (is_redirect(t->type)) {
            if (t->type == TOK_ERR_TO_OUT) {
                c->err_to_out = 1;
                free(c->err_file);
                c->err_file = NULL;
                (*i)++;
                continue;
            }
            if (*i + 1 >= tl->len || tl->items[*i + 1].type != TOK_WORD) {
                *err = "expected a file name after redirection";
                c->argv[c->argc] = NULL;
                return -1;
            }
            const char *f = tl->items[*i + 1].text;
            switch (t->type) {
            case TOK_LT: set_file(&c->in_file, f); break;
            case TOK_GT: set_file(&c->out_file, f); c->out_append = 0; break;
            case TOK_GTGT: set_file(&c->out_file, f); c->out_append = 1; break;
            case TOK_ERR_GT: set_file(&c->err_file, f); c->err_append = 0; c->err_to_out = 0; break;
            case TOK_ERR_GTGT: set_file(&c->err_file, f); c->err_append = 1; c->err_to_out = 0; break;
            default: break;
            }
            *i += 2;
        } else {
            break;
        }
    }
    c->argv[c->argc] = NULL;
    if (c->argc == 0) {
        *err = "missing command";
        return -1;
    }
    return 0;
}

static int parse_pipeline(const token_list *tl, size_t *i, pipeline *pl, const char **err) {
    int cap = 2;
    pl->cmds = xmalloc(sizeof(command) * (size_t)cap);
    pl->ncmds = 0;
    for (;;) {
        if (pl->ncmds == cap) {
            cap *= 2;
            pl->cmds = xrealloc(pl->cmds, sizeof(command) * (size_t)cap);
        }
        int rc = parse_command(tl, i, &pl->cmds[pl->ncmds], err);
        pl->ncmds++; /* count it even on failure so it gets freed */
        if (rc != 0) return -1;
        if (*i < tl->len && tl->items[*i].type == TOK_PIPE) {
            (*i)++;
            continue;
        }
        return 0;
    }
}

int parse(const token_list *tl, command_list *out, const char **err) {
    out->items = NULL;
    out->nitems = 0;
    *err = NULL;
    if (tl->len == 0) return 0;

    int cap = 2;
    out->items = xmalloc(sizeof(list_item) * (size_t)cap);
    size_t i = 0;
    connector next_conn = CONN_SEQ;

    while (i < tl->len) {
        if (out->nitems == cap) {
            cap *= 2;
            out->items = xrealloc(out->items, sizeof(list_item) * (size_t)cap);
        }
        list_item *it = &out->items[out->nitems++];
        memset(it, 0, sizeof *it);
        it->conn = next_conn;
        if (parse_pipeline(tl, &i, &it->pl, err) != 0) {
            command_list_free(out);
            return -1;
        }
        if (i >= tl->len) break;

        token_type t = tl->items[i].type;
        i++;
        if (t == TOK_SEMI) {
            next_conn = CONN_SEQ;
        } else if (t == TOK_AMP) {
            it->background = 1;
            next_conn = CONN_SEQ;
        } else if (t == TOK_AND || t == TOK_OR) {
            next_conn = (t == TOK_AND) ? CONN_AND : CONN_OR;
            if (i >= tl->len) {
                *err = t == TOK_AND ? "expected a command after '&&'" : "expected a command after '||'";
                command_list_free(out);
                return -1;
            }
        } else {
            *err = "unexpected token";
            command_list_free(out);
            return -1;
        }
    }
    return 0;
}

char *pipeline_to_string(const pipeline *pl) {
    size_t n = 1;
    for (int i = 0; i < pl->ncmds; i++)
        for (int j = 0; j < pl->cmds[i].argc; j++) n += strlen(pl->cmds[i].argv[j]) + 3;
    char *s = xmalloc(n + 4);
    s[0] = '\0';
    for (int i = 0; i < pl->ncmds; i++) {
        if (i) strcat(s, " | ");
        for (int j = 0; j < pl->cmds[i].argc; j++) {
            if (j) strcat(s, " ");
            strcat(s, pl->cmds[i].argv[j]);
        }
    }
    return s;
}
