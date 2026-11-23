/* main.c - vigil entry point: argument handling, REPL, job-control setup. */
#include "shell.h"

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define VIGIL_VERSION "1.0.0"

static void on_sigint(int sig) {
    (void)sig;
    (void)!write(STDOUT_FILENO, "\n", 1);
}

/* Take control of the terminal so we can do job control (glibc manual,
 * "Initializing the Shell"). */
static void init_interactive(void) {
    g_shell.terminal_fd = STDIN_FILENO;
    while (tcgetpgrp(g_shell.terminal_fd) != (g_shell.shell_pgid = getpgrp()))
        kill(-g_shell.shell_pgid, SIGTTIN);

    signal(SIGQUIT, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sigint; /* no SA_RESTART: interrupts getline() */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    g_shell.shell_pgid = getpid();
    if (setpgid(g_shell.shell_pgid, g_shell.shell_pgid) < 0 && errno != EPERM) {
        perror("vigil: setpgid");
        exit(1);
    }
    tcsetpgrp(g_shell.terminal_fd, g_shell.shell_pgid);
}

static void print_prompt(void) {
    char cwd[PATH_MAX];
    const char *shown = "?";
    char buf[PATH_MAX + 2];
    if (getcwd(cwd, sizeof cwd)) {
        const char *home = getenv("HOME");
        size_t hl = home ? strlen(home) : 0;
        if (home && hl > 1 && strncmp(cwd, home, hl) == 0 && (cwd[hl] == '/' || cwd[hl] == '\0')) {
            snprintf(buf, sizeof buf, "~%s", cwd + hl);
            shown = buf;
        } else {
            shown = cwd;
        }
    }
    if (g_shell.last_status != 0) printf("vigil:%s [%d]$ ", shown, g_shell.last_status);
    else printf("vigil:%s$ ", shown);
    fflush(stdout);
}

/* Runs one line of input and records it in the audit log. */
static void run_line(const char *line) {
    token_list tl;
    command_list cl;
    const char *err;

    if (lex(line, &tl, &err) != 0) {
        fprintf(stderr, "vigil: syntax error: %s\n", err);
        g_shell.last_status = 2;
        audit_record(line, 2);
        return;
    }
    if (tl.len == 0) { /* blank or comment */
        token_list_free(&tl);
        return;
    }
    if (parse(&tl, &cl, &err) != 0) {
        fprintf(stderr, "vigil: syntax error: %s\n", err);
        token_list_free(&tl);
        g_shell.last_status = 2;
        audit_record(line, 2);
        return;
    }
    token_list_free(&tl);
    int status = exec_list(&cl);
    command_list_free(&cl);
    audit_record(line, status);
}

static int run_stream(FILE *in) {
    char *line = NULL;
    size_t cap = 0;
    while (!g_shell.should_exit) {
        if (g_shell.interactive) {
            jobs_reap(1);
            print_prompt();
        } else {
            jobs_reap(0);
        }
        errno = 0;
        ssize_t n = getline(&line, &cap, in);
        if (n < 0) {
            if (errno == EINTR) { /* Ctrl-C at the prompt */
                clearerr(in);
                continue;
            }
            if (g_shell.interactive) printf("exit\n");
            break;
        }
        if (n > 0 && line[n - 1] == '\n') line[--n] = '\0';
        run_line(line);
    }
    free(line);
    return g_shell.should_exit ? g_shell.exit_code : g_shell.last_status;
}

static void usage(void) {
    printf("usage: vigil [--no-audit] [-c command | script]\n"
           "       vigil --version\n\n"
           "Environment:\n"
           "  VIGIL_AUDIT_FILE   audit log path (default ~/.vigil_audit)\n"
           "  VIGIL_AUDIT_KEY    HMAC key for the audit chain (removed from the environment at startup)\n"
           "  VIGIL_AUDIT=off    disable audit logging\n");
}

int main(int argc, char **argv) {
    memset(&g_shell, 0, sizeof g_shell);
    const char *cmd_arg = NULL, *script = NULL;
    int no_audit = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "vigil: -c requires an argument\n"); return 2; }
            cmd_arg = argv[++i];
        } else if (strcmp(argv[i], "--no-audit") == 0) {
            no_audit = 1;
        } else if (strcmp(argv[i], "--version") == 0) {
            printf("vigil %s\n", VIGIL_VERSION);
            return 0;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage();
            return 0;
        } else if (!script && argv[i][0] != '-') {
            script = argv[i];
        } else {
            fprintf(stderr, "vigil: unknown option '%s'\n", argv[i]);
            usage();
            return 2;
        }
    }

    audit_init();
    if (no_audit) audit_disable();

    if (cmd_arg) {
        run_line(cmd_arg);
        jobs_reap(0);
        return g_shell.should_exit ? g_shell.exit_code : g_shell.last_status;
    }

    FILE *in = stdin;
    if (script) {
        in = fopen(script, "r");
        if (!in) { fprintf(stderr, "vigil: %s: %s\n", script, strerror(errno)); return 127; }
    } else if (isatty(STDIN_FILENO)) {
        g_shell.interactive = 1;
        init_interactive();
    }

    int rc = run_stream(in);
    if (script) fclose(in);
    return rc;
}
