/* builtins.c - commands implemented inside the shell. */
#include "shell.h"

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static int b_cd(int argc, char **argv) {
    const char *dir;
    int print = 0;
    if (argc < 2) {
        dir = getenv("HOME");
        if (!dir) { fprintf(stderr, "cd: HOME not set\n"); return 1; }
    } else if (strcmp(argv[1], "-") == 0) {
        dir = getenv("OLDPWD");
        if (!dir) { fprintf(stderr, "cd: OLDPWD not set\n"); return 1; }
        print = 1;
    } else {
        dir = argv[1];
    }
    char old[PATH_MAX];
    if (!getcwd(old, sizeof old)) old[0] = '\0';
    char *target = xstrdup(dir); /* dir may point into the environment */
    if (chdir(target) != 0) {
        fprintf(stderr, "cd: %s: %s\n", target, strerror(errno));
        free(target);
        return 1;
    }
    free(target);
    char now[PATH_MAX];
    if (old[0]) setenv("OLDPWD", old, 1);
    if (getcwd(now, sizeof now)) {
        setenv("PWD", now, 1);
        if (print) printf("%s\n", now);
    }
    return 0;
}

static int b_exit(int argc, char **argv) {
    g_shell.should_exit = 1;
    if (argc > 1) {
        char *end;
        long v = strtol(argv[1], &end, 10);
        if (*end) {
            fprintf(stderr, "exit: %s: numeric argument required\n", argv[1]);
            g_shell.exit_code = 2;
            return 2;
        }
        g_shell.exit_code = (int)(v & 0xff);
    } else {
        g_shell.exit_code = g_shell.last_status;
    }
    return g_shell.exit_code;
}

static int b_pwd(int argc, char **argv) {
    (void)argc; (void)argv;
    char buf[PATH_MAX];
    if (!getcwd(buf, sizeof buf)) { perror("pwd"); return 1; }
    printf("%s\n", buf);
    return 0;
}

static int valid_name(const char *s, size_t n) {
    if (n == 0 || !((*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z') || *s == '_')) return 0;
    for (size_t i = 1; i < n; i++) {
        char c = s[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'))
            return 0;
    }
    return 1;
}

static int b_export(int argc, char **argv) {
    extern char **environ;
    if (argc == 1) {
        for (char **e = environ; *e; e++) printf("export %s\n", *e);
        return 0;
    }
    int rc = 0;
    for (int i = 1; i < argc; i++) {
        char *eq = strchr(argv[i], '=');
        size_t n = eq ? (size_t)(eq - argv[i]) : strlen(argv[i]);
        if (!valid_name(argv[i], n)) {
            fprintf(stderr, "export: '%s': not a valid identifier\n", argv[i]);
            rc = 1;
            continue;
        }
        if (eq) {
            char *name = xstrdup(argv[i]);
            name[n] = '\0';
            setenv(name, eq + 1, 1);
            free(name);
        }
    }
    return rc;
}

static int b_unset(int argc, char **argv) {
    for (int i = 1; i < argc; i++) unsetenv(argv[i]);
    return 0;
}

static int b_jobs(int argc, char **argv) {
    (void)argc; (void)argv;
    jobs_reap(0);
    jobs_print();
    return 0;
}

static job *pick_job(int argc, char **argv, const char *who) {
    job *j;
    if (argc > 1) {
        const char *s = argv[1][0] == '%' ? argv[1] + 1 : argv[1];
        j = job_find(atoi(s));
    } else {
        j = job_most_recent();
    }
    if (!j) fprintf(stderr, "%s: no such job\n", who);
    return j;
}

static void continue_job(job *j) {
    if (g_shell.interactive) {
        kill(-j->pgid, SIGCONT);
    } else {
        for (int i = 0; i < j->npids; i++)
            if (!j->finished[i]) kill(j->pids[i], SIGCONT);
    }
}

static int b_fg(int argc, char **argv) {
    job *j = pick_job(argc, argv, "fg");
    if (!j) return 1;
    printf("%s\n", j->cmdline);
    fflush(stdout);
    continue_job(j);
    return job_wait_foreground(j);
}

static int b_bg(int argc, char **argv) {
    job *j = pick_job(argc, argv, "bg");
    if (!j) return 1;
    continue_job(j);
    j->state = JOB_RUNNING;
    printf("[%d]  %s &\n", j->id, j->cmdline);
    return 0;
}

static int b_limit(int argc, char **argv) {
    /* Only reached with no command: show the shell's current limits. */
    (void)argc; (void)argv;
    limits_print_current();
    return 0;
}

static int b_help(int argc, char **argv) {
    (void)argc; (void)argv;
    printf(
        "vigil - a small POSIX-style shell with a tamper-evident audit log\n\n"
        "Builtins:\n"
        "  cd [dir|-]            change directory\n"
        "  pwd                   print working directory\n"
        "  export [NAME=value]   set or list environment variables\n"
        "  unset NAME...         remove environment variables\n"
        "  jobs | fg [%%n] | bg [%%n]   job control\n"
        "  limit k=v... -- cmd   run cmd with resource limits\n"
        "                        (cpu=SEC mem=SIZE fsize=SIZE files=N nproc=N)\n"
        "  audit [tail N | verify [--anchor H] | head | path]\n"
        "  exit [n]              leave the shell\n\n"
        "Syntax: cmd | cmd, < > >> 2> 2>> 2>&1, &&, ||, ;, &, 'quotes', \"$VAR\", ~\n");
    return 0;
}

static const struct {
    const char *name;
    builtin_fn fn;
    int parent_only;
} BUILTINS[] = {
    {"cd", b_cd, 1},       {"exit", b_exit, 1},   {"export", b_export, 1},
    {"unset", b_unset, 1}, {"jobs", b_jobs, 1},   {"fg", b_fg, 1},
    {"bg", b_bg, 1},       {"pwd", b_pwd, 0},     {"help", b_help, 0},
    {"audit", builtin_audit, 0}, {"limit", b_limit, 0},
};

builtin_fn builtin_lookup(const char *name) {
    for (size_t i = 0; i < sizeof BUILTINS / sizeof *BUILTINS; i++)
        if (strcmp(BUILTINS[i].name, name) == 0) return BUILTINS[i].fn;
    return NULL;
}

int builtin_must_run_in_parent(const char *name) {
    for (size_t i = 0; i < sizeof BUILTINS / sizeof *BUILTINS; i++)
        if (strcmp(BUILTINS[i].name, name) == 0) return BUILTINS[i].parent_only;
    return 0;
}
