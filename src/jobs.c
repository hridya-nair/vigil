/* jobs.c - job table, waiting, and job-control helpers. */
#include "shell.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static job *g_jobs = NULL;

static int next_job_id(void) {
    int id = 1;
    for (;;) {
        int used = 0;
        for (job *j = g_jobs; j; j = j->next)
            if (j->id == id) used = 1;
        if (!used) return id;
        id++;
    }
}

job *job_add(pid_t pgid, pid_t *pids, int npids, const char *cmdline, int background) {
    job *j = xmalloc(sizeof *j);
    j->id = background ? next_job_id() : 0;
    j->pgid = pgid;
    j->npids = npids;
    j->pids = xmalloc(sizeof(pid_t) * (size_t)npids);
    memcpy(j->pids, pids, sizeof(pid_t) * (size_t)npids);
    j->finished = calloc((size_t)npids, sizeof(int));
    if (!j->finished) { perror("vigil: calloc"); exit(1); }
    j->status = 0;
    j->state = JOB_RUNNING;
    j->cmdline = xstrdup(cmdline);
    j->next = g_jobs;
    g_jobs = j;
    return j;
}

void job_remove(job *j) {
    job **pp = &g_jobs;
    while (*pp && *pp != j) pp = &(*pp)->next;
    if (*pp) *pp = j->next;
    free(j->pids);
    free(j->finished);
    free(j->cmdline);
    free(j);
}

job *job_find(int id) {
    for (job *j = g_jobs; j; j = j->next)
        if (j->id == id) return j;
    return NULL;
}

job *job_most_recent(void) {
    job *best = NULL;
    for (job *j = g_jobs; j; j = j->next)
        if (j->id > 0 && (!best || j->id > best->id)) best = j;
    return best;
}

int jobs_count(void) {
    int n = 0;
    for (job *j = g_jobs; j; j = j->next)
        if (j->id > 0) n++;
    return n;
}

int status_from_wait(int ws, int report) {
    if (WIFEXITED(ws)) return WEXITSTATUS(ws);
    if (WIFSIGNALED(ws)) {
        int sig = WTERMSIG(ws);
        if (report && sig != SIGINT && sig != SIGPIPE) {
            const char *why;
            switch (sig) {
            case SIGXCPU: why = "CPU time limit exceeded"; break;
            case SIGXFSZ: why = "file size limit exceeded"; break;
            case SIGKILL: why = "killed"; break;
            default: why = strsignal(sig); break;
            }
            const char *core = "";
#ifdef WCOREDUMP
            if (WCOREDUMP(ws)) core = " (core dumped)";
#endif
            fprintf(stderr, "vigil: %s%s\n", why, core);
        }
        if (report && sig == SIGINT && g_shell.interactive) fputc('\n', stderr);
        return 128 + sig;
    }
    return 1;
}

static int all_finished(job *j) {
    for (int i = 0; i < j->npids; i++)
        if (!j->finished[i]) return 0;
    return 1;
}

static void give_terminal_to(pid_t pgid) {
    if (g_shell.interactive) tcsetpgrp(g_shell.terminal_fd, pgid);
}

/* Waits for every process of a foreground job, or until it is stopped. */
int job_wait_foreground(job *j) {
    give_terminal_to(j->pgid);
    j->state = JOB_RUNNING;

    for (int i = 0; i < j->npids; i++) {
        if (j->finished[i]) continue;
        int ws;
        pid_t r;
        do {
            r = waitpid(j->pids[i], &ws, WUNTRACED);
        } while (r < 0 && errno == EINTR);
        if (r < 0) {
            j->finished[i] = 1;
            continue;
        }
        if (WIFSTOPPED(ws)) {
            j->state = JOB_STOPPED;
            break;
        }
        j->finished[i] = 1;
        if (i == j->npids - 1) j->status = status_from_wait(ws, 1);
        else (void)status_from_wait(ws, 0);
    }

    give_terminal_to(g_shell.shell_pgid);

    if (j->state == JOB_STOPPED) {
        if (j->id == 0) j->id = next_job_id();
        fprintf(stderr, "\n[%d]+  Stopped\t\t%s\n", j->id, j->cmdline);
        return 128 + SIGTSTP;
    }
    int st = j->status;
    job_remove(j);
    return st;
}

/* Collects status of background jobs without blocking. */
void jobs_reap(int report) {
    job *j = g_jobs;
    while (j) {
        job *next = j->next;
        for (int i = 0; i < j->npids; i++) {
            if (j->finished[i]) continue;
            int ws;
            int flags = WNOHANG | WUNTRACED;
#ifdef WCONTINUED
            flags |= WCONTINUED;
#endif
            pid_t r = waitpid(j->pids[i], &ws, flags);
            if (r <= 0) {
                if (r < 0) j->finished[i] = 1; /* already gone */
                continue;
            }
            if (WIFSTOPPED(ws)) {
                j->state = JOB_STOPPED;
            }
#ifdef WIFCONTINUED
            else if (WIFCONTINUED(ws)) {
                j->state = JOB_RUNNING;
            }
#endif
            else {
                j->finished[i] = 1;
                if (i == j->npids - 1) j->status = status_from_wait(ws, 0);
            }
        }
        if (all_finished(j)) {
            if (report)
                fprintf(stderr, "[%d]   %s\t\t%s\n", j->id,
                        j->status == 0 ? "Done" : "Exit", j->cmdline);
            job_remove(j);
        }
        j = next;
    }
}

void jobs_print(void) {
    /* print in id order */
    int max = 0;
    for (job *j = g_jobs; j; j = j->next)
        if (j->id > max) max = j->id;
    for (int id = 1; id <= max; id++) {
        job *j = job_find(id);
        if (!j) continue;
        printf("[%d]  %-8s %s\n", j->id, j->state == JOB_STOPPED ? "Stopped" : "Running",
               j->cmdline);
    }
}
