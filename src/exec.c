/* exec.c - runs parsed command lists: pipelines, redirections, builtins,
 * background jobs and resource-limited commands. */
#include "shell.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* Opens a redirection target and moves it onto target_fd. */
static int redirect_to(const char *path, int flags, int target_fd) {
    int fd = open(path, flags, 0644);
    if (fd < 0) {
        fprintf(stderr, "vigil: %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (fd != target_fd) {
        if (dup2(fd, target_fd) < 0) {
            perror("vigil: dup2");
            close(fd);
            return -1;
        }
        close(fd);
    }
    return 0;
}

static int apply_redirections(const command *c) {
    if (c->in_file && redirect_to(c->in_file, O_RDONLY, STDIN_FILENO) != 0) return -1;
    if (c->out_file &&
        redirect_to(c->out_file, O_WRONLY | O_CREAT | (c->out_append ? O_APPEND : O_TRUNC),
                    STDOUT_FILENO) != 0)
        return -1;
    if (c->err_to_out) {
        if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) return -1;
    } else if (c->err_file &&
               redirect_to(c->err_file, O_WRONLY | O_CREAT | (c->err_append ? O_APPEND : O_TRUNC),
                           STDERR_FILENO) != 0) {
        return -1;
    }
    return 0;
}

/* Runs a builtin inside the shell process, with redirections applied
 * temporarily and then undone. */
static int run_builtin_in_parent(command *c, builtin_fn fn) {
    int saved[3];
    for (int i = 0; i < 3; i++) saved[i] = fcntl(i, F_DUPFD_CLOEXEC, 10);

    int status;
    if (apply_redirections(c) != 0) {
        status = 1;
    } else {
        status = fn(c->argc, c->argv);
    }
    fflush(stdout);
    fflush(stderr);

    for (int i = 0; i < 3; i++) {
        if (saved[i] >= 0) {
            dup2(saved[i], i);
            close(saved[i]);
        }
    }
    return status;
}

static void reset_child_signals(void) {
    int sigs[] = {SIGINT, SIGQUIT, SIGTSTP, SIGTTIN, SIGTTOU, SIGCHLD, SIGPIPE};
    for (size_t i = 0; i < sizeof sigs / sizeof *sigs; i++) signal(sigs[i], SIG_DFL);
}

static void child_exec(command *c, char **argv, const limits *lim, int has_limits) {
    if (apply_redirections(c) != 0) _exit(1);
    if (has_limits && limits_apply(lim) != 0) _exit(1);

    builtin_fn fn = builtin_lookup(argv[0]);
    if (fn && !(has_limits && strcmp(argv[0], "limit") == 0)) {
        int argc = 0;
        while (argv[argc]) argc++;
        int st = fn(argc, argv);
        fflush(stdout);
        _exit(st);
    }

    execvp(argv[0], argv);
    int e = errno;
    if (e == ENOENT) fprintf(stderr, "vigil: %s: command not found\n", argv[0]);
    else fprintf(stderr, "vigil: %s: %s\n", argv[0], strerror(e));
    _exit(e == ENOENT ? 127 : 126);
}

/* Expands one redirection target in place. */
static int expand_file(char **slot) {
    if (!*slot) return 0;
    const char *err;
    char *v = expand_word(*slot, &err);
    if (!v) {
        fprintf(stderr, "vigil: %s: %s\n", *slot, err ? err : "ambiguous redirect");
        return -1;
    }
    free(*slot);
    *slot = v;
    return 0;
}

/* Expands every word of a pipeline right before it runs. Words that expand
 * to nothing are dropped. Returns -1 on error. */
static int expand_pipeline(pipeline *pl) {
    for (int i = 0; i < pl->ncmds; i++) {
        command *c = &pl->cmds[i];
        int out = 0;
        for (int j = 0; j < c->argc; j++) {
            const char *err;
            char *v = expand_word(c->argv[j], &err);
            if (!v && err) {
                fprintf(stderr, "vigil: %s\n", err);
                for (int k = j; k < c->argc; k++) free(c->argv[k]);
                c->argc = out;
                c->argv[out] = NULL;
                return -1;
            }
            free(c->argv[j]);
            if (v) c->argv[out++] = v;
        }
        c->argc = out;
        c->argv[out] = NULL;
        if (expand_file(&c->in_file) || expand_file(&c->out_file) || expand_file(&c->err_file))
            return -1;
    }
    return 0;
}

/* NAME=value [NAME=value...] with no command sets environment variables. */
static int is_assignment(const char *s) {
    const char *eq = strchr(s, '=');
    if (!eq || eq == s) return 0;
    if (!((*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z') || *s == '_')) return 0;
    for (const char *p = s + 1; p < eq; p++)
        if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '_'))
            return 0;
    return 1;
}

static int run_pipeline(pipeline *pl, int background) {
    if (expand_pipeline(pl) != 0) return 1;
    for (int i = 0; i < pl->ncmds; i++) {
        if (pl->cmds[i].argc == 0) {
            if (pl->ncmds == 1) return 0; /* e.g. a lone $EMPTY */
            fprintf(stderr, "vigil: empty command in pipeline\n");
            return 1;
        }
    }

    if (pl->ncmds == 1 && !background) {
        command *c = &pl->cmds[0];
        int all = 1;
        for (int j = 0; j < c->argc; j++) all &= is_assignment(c->argv[j]);
        if (all) {
            for (int j = 0; j < c->argc; j++) {
                char *eq = strchr(c->argv[j], '=');
                *eq = '\0';
                setenv(c->argv[j], eq + 1, 1);
                *eq = '=';
            }
            return 0;
        }
    }

    /* Fast path: a lone builtin that changes shell state (cd, export, ...)
     * must run in this process, not a child. */
    if (pl->ncmds == 1 && !background) {
        command *c = &pl->cmds[0];
        builtin_fn fn = builtin_lookup(c->argv[0]);
        int is_limit_with_cmd = strcmp(c->argv[0], "limit") == 0 && c->argc > 1;
        if (fn && !is_limit_with_cmd) return run_builtin_in_parent(c, fn);
    }

    /* Validate `limit` prefixes before forking anything. */
    limits *lims = calloc((size_t)pl->ncmds, sizeof *lims);
    int *cmd_start = calloc((size_t)pl->ncmds, sizeof *cmd_start);
    pid_t *pids = calloc((size_t)pl->ncmds, sizeof *pids);
    if (!lims || !cmd_start || !pids) { perror("vigil: calloc"); exit(1); }

    for (int i = 0; i < pl->ncmds; i++) {
        command *c = &pl->cmds[i];
        if (strcmp(c->argv[0], "limit") == 0 && c->argc > 1) {
            cmd_start[i] = limits_parse(c->argv, &lims[i]);
            if (cmd_start[i] < 0) {
                free(lims); free(cmd_start); free(pids);
                return 2;
            }
        }
    }

    char *cmdline = pipeline_to_string(pl);
    pid_t pgid = 0;
    int prev_read = -1;
    int nstarted = 0;

    for (int i = 0; i < pl->ncmds; i++) {
        int fds[2] = {-1, -1};
        if (i < pl->ncmds - 1 && pipe(fds) != 0) {
            perror("vigil: pipe");
            break;
        }

        fflush(stdout);
        fflush(stderr);
        pid_t pid = fork();
        if (pid < 0) {
            perror("vigil: fork");
            if (fds[0] >= 0) { close(fds[0]); close(fds[1]); }
            break;
        }

        if (pid == 0) {
            if (g_shell.interactive) {
                setpgid(0, pgid);
            }
            reset_child_signals();
            if (prev_read >= 0) {
                dup2(prev_read, STDIN_FILENO);
                close(prev_read);
            } else if (background && !g_shell.interactive) {
                int dn = open("/dev/null", O_RDONLY);
                if (dn >= 0) { dup2(dn, STDIN_FILENO); close(dn); }
            }
            if (fds[1] >= 0) {
                dup2(fds[1], STDOUT_FILENO);
                close(fds[1]);
                close(fds[0]);
            }
            command *c = &pl->cmds[i];
            child_exec(c, c->argv + cmd_start[i], &lims[i], cmd_start[i] > 0);
        }

        /* parent */
        if (g_shell.interactive) {
            if (pgid == 0) pgid = pid;
            setpgid(pid, pgid); /* also done in the child: avoids a race */
        }
        pids[nstarted++] = pid;
        if (prev_read >= 0) close(prev_read);
        if (fds[1] >= 0) close(fds[1]);
        prev_read = fds[0];
    }
    if (prev_read >= 0) close(prev_read);

    int status = 0;
    if (nstarted == 0) {
        status = 1;
    } else {
        job *j = job_add(pgid, pids, nstarted, cmdline, background);
        if (nstarted < pl->ncmds) {
            /* pipeline broke halfway: wait for what we started */
            status = job_wait_foreground(j);
            status = 1;
        } else if (background) {
            if (g_shell.interactive) fprintf(stderr, "[%d] %ld\n", j->id, (long)pids[nstarted - 1]);
            status = 0;
        } else {
            status = job_wait_foreground(j);
        }
    }

    free(cmdline);
    free(lims);
    free(cmd_start);
    free(pids);
    return status;
}

int exec_list(command_list *cl) {
    int status = g_shell.last_status;
    for (int i = 0; i < cl->nitems && !g_shell.should_exit; i++) {
        list_item *it = &cl->items[i];
        if (it->conn == CONN_AND && status != 0) continue;
        if (it->conn == CONN_OR && status == 0) continue;
        status = run_pipeline(&it->pl, it->background);
        g_shell.last_status = status;
    }
    return status;
}
