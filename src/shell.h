/* shell.h - shared types for the vigil shell. */
#ifndef VIGIL_SHELL_H
#define VIGIL_SHELL_H

#include <stddef.h>
#include <sys/types.h>

/* ---------- global shell state ---------- */

typedef struct {
    int interactive;      /* stdin is a terminal and we own job control */
    int last_status;      /* value of $? */
    pid_t shell_pgid;
    int terminal_fd;
    int should_exit;
    int exit_code;
} shell_state;

extern shell_state g_shell;

/* ---------- lexer ---------- */

typedef enum {
    TOK_WORD,
    TOK_PIPE,       /* |  */
    TOK_AND,        /* && */
    TOK_OR,         /* || */
    TOK_SEMI,       /* ;  */
    TOK_AMP,        /* &  */
    TOK_LT,         /* <  */
    TOK_GT,         /* >  */
    TOK_GTGT,       /* >> */
    TOK_ERR_GT,     /* 2> */
    TOK_ERR_GTGT,   /* 2>> */
    TOK_ERR_TO_OUT, /* 2>&1 */
} token_type;

typedef struct {
    token_type type;
    char *text; /* only for TOK_WORD: raw text, quotes and $ still present */
} token;

typedef struct {
    token *items;
    size_t len, cap;
} token_list;

/* Returns 0 on success; on a syntax error returns -1 and sets *err. */
int lex(const char *input, token_list *out, const char **err);
void token_list_free(token_list *tl);
/* Expands quotes, escapes, $VAR, ~ in one raw word. Returns NULL when the
 * word expands to nothing (unquoted empty) or on error (*err set). */
char *expand_word(const char *raw, const char **err);

/* ---------- parser / AST ---------- */

typedef struct {
    char **argv;          /* NULL-terminated */
    int argc;
    char *in_file;        /* <  */
    char *out_file;       /* > or >> */
    int out_append;
    char *err_file;       /* 2> or 2>> */
    int err_append;
    int err_to_out;       /* 2>&1 */
} command;

typedef struct {
    command *cmds;
    int ncmds;
} pipeline;

typedef enum { CONN_SEQ, CONN_AND, CONN_OR } connector;

typedef struct {
    pipeline pl;
    connector conn; /* how this item relates to the previous one */
    int background; /* terminated by & */
} list_item;

typedef struct {
    list_item *items;
    int nitems;
} command_list;

int parse(const token_list *tl, command_list *out, const char **err);
void command_list_free(command_list *cl);
char *pipeline_to_string(const pipeline *pl);

/* ---------- execution ---------- */

int exec_list(command_list *cl);

/* ---------- builtins ---------- */

typedef int (*builtin_fn)(int argc, char **argv);
builtin_fn builtin_lookup(const char *name);
/* Builtins that must run inside the shell process to have any effect. */
int builtin_must_run_in_parent(const char *name);

/* ---------- jobs ---------- */

typedef enum { JOB_RUNNING, JOB_STOPPED, JOB_DONE } job_state;

typedef struct job {
    int id;
    pid_t pgid;
    pid_t *pids;
    int *finished;
    int npids;
    int status;     /* status of the last process in the pipeline */
    job_state state;
    char *cmdline;
    struct job *next;
} job;

job *job_add(pid_t pgid, pid_t *pids, int npids, const char *cmdline, int background);
void job_remove(job *j);
job *job_find(int id);
job *job_most_recent(void);
int job_wait_foreground(job *j); /* returns shell-style exit status */
void jobs_reap(int report);
void jobs_print(void);
int jobs_count(void);

/* Convert a wait() status to a shell exit status and print a message for
 * abnormal terminations. */
int status_from_wait(int wstatus, int report);

/* ---------- limit (resource sandbox) ---------- */

typedef struct {
    int set_cpu, set_mem, set_fsize, set_files, set_nproc;
    unsigned long long cpu, mem, fsize, files, nproc;
} limits;

/* Parses "limit k=v ... [--] cmd args". On success returns the index in argv
 * where the real command starts, or -1 on error (message printed). */
int limits_parse(char **argv, limits *out);
int limits_apply(const limits *l); /* in the child; 0 on success */
void limits_print_current(void);

/* ---------- audit log ---------- */

void audit_init(void);
void audit_disable(void);
void audit_record(const char *cmdline, int status);
int builtin_audit(int argc, char **argv);

/* ---------- util ---------- */

void *xmalloc(size_t n);
void *xrealloc(void *p, size_t n);
char *xstrdup(const char *s);

#endif
