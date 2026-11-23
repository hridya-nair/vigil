# vigil: a Unix shell with a tamper-evident audit log

![CI](https://github.com/hridya-nair/vigil/actions/workflows/ci.yml/badge.svg)

`vigil` is a POSIX-style command shell written from scratch in C (no libraries beyond libc). It does
what you expect a shell to do: pipelines, redirection, `&&`/`||`, background jobs and job control. On top of
that it adds three security features I couldn't find together in other small shells:

1. **Tamper-evident audit log.** Every command line is recorded in a SHA-256 hash chain (optionally
   HMAC-keyed). If anyone edits, deletes, reorders or truncates a record, `audit verify` finds it and tells
   you which record broke.
2. **Per-command resource sandbox.** `limit cpu=2 mem=256M -- ./untrusted` runs a single command under kernel
   resource limits (`setrlimit`) without affecting the shell itself.
3. **Injection-safe expansion.** Variables are never word-split or glob-expanded, so a value like
   `"a; rm -rf ~"` is always one literal argument.

The SHA-256 / HMAC implementation is my own and is checked against the FIPS 180-4 and RFC 4231 test vectors.
The parser is fuzzed with libFuzzer under AddressSanitizer + UBSan in CI.

```
$ ./vigil
vigil:~/vigil$ echo "hello" | tr a-z A-Z
HELLO
vigil:~/vigil$ limit cpu=1 -- sh -c "while :; do :; done"
vigil: CPU time limit exceeded
vigil:~/vigil [152]$ audit tail 3
1      2026-11-23 02:49:43  [  0]  echo "hello" | tr a-z A-Z
2      2026-11-23 02:49:44  [152]  limit cpu=1 -- sh -c "while :; do :; done"
3      2026-11-23 02:49:50  [  0]  audit tail 3
vigil:~/vigil$ audit verify
audit: OK  3 records, chain intact
head: 27cd68a2047113d2eeca9251d5d8efb0a475ee461bdf649128038d60241489cc
```

Someone edits the log to hide a command:

```
$ sed -i 's/echo offline/echo HIDDEN/' ~/.vigil_audit
$ vigil -c 'audit verify'
audit: TAMPERED at line 4 (expected record 4): hash mismatch (record contents were modified)
```

## Build and run

Needs a C11 compiler and `make`. Tested on Linux and macOS.

```sh
make            # builds ./vigil
./vigil         # interactive
./vigil -c 'echo hi | wc -c'
./vigil script.vsh
make test       # 81 integration tests + SHA-256/HMAC known-answer tests
make test-asan  # same tests under AddressSanitizer + UndefinedBehaviorSanitizer
make fuzz       # libFuzzer on the lexer/parser/expander (Linux, clang)
```

## Features

| Area | Supported |
|---|---|
| Commands | `PATH` lookup, exit statuses, `127` not found / `126` not executable |
| Operators | `|` pipelines of any length, `&&`, `||`, `;`, `&` |
| Redirection | `<`, `>`, `>>`, `2>`, `2>>`, `2>&1` (on builtins too) |
| Quoting | `'single'`, `"double"`, `\` escapes, `# comments` |
| Expansion | `$VAR`, `${VAR}`, `$?`, `$$`, `~`, `~/path`, `NAME=value` assignment |
| Job control | `cmd &`, Ctrl-Z, `jobs`, `fg %n`, `bg %n`, Ctrl-C kills the job, not the shell |
| Builtins | `cd [-]`, `pwd`, `export`, `unset`, `exit [n]`, `jobs`, `fg`, `bg`, `limit`, `audit`, `help` |
| Modes | interactive (with prompt showing the last exit status), `-c "cmd"`, script file, piped stdin |

## Security design

### 1. Hash-chained audit log

Each command line becomes one tab-separated record in `~/.vigil_audit` (or `$VIGIL_AUDIT_FILE`):

```
seq  time  uid  exit_status  cwd  command  alg  prev_mac  mac
```

`mac = SHA-256(fields 1..8)`. With `VIGIL_AUDIT_KEY` set it's `HMAC-SHA256(key, fields 1..8)` instead.
Every record includes the previous record's `mac`, so they form a chain like a Git history or a blockchain:
changing any byte breaks that record's hash and every link after it.

`audit verify` recomputes the whole chain and reports the first bad record, with the reason:

| Attack | How it is detected |
|---|---|
| Edit a command, status or timestamp | recomputed hash ≠ stored hash |
| Delete or insert a record | sequence gap + broken `prev_mac` link |
| Reorder records | broken `prev_mac` link |
| Truncate the end of the log | `audit verify --anchor <hash>`: an anchor saved earlier is missing |
| Recompute the whole chain after editing | defeated by the HMAC key: an attacker without the key cannot forge valid MACs |
| Downgrade keyed records to unkeyed | verifying with the key rejects any unkeyed `h` record |

Hardening details:
- The log is created `0600`, opened with `O_NOFOLLOW` (a symlink planted at the log path is refused, not
  followed), and must be a regular file.
- Writers take an exclusive `flock()` and read the chain tail *under the lock*, so several shells writing
  the same log still produce one valid chain.
- `VIGIL_AUDIT_KEY` is read once at startup and then **removed from the environment**, so the key isn't
  passed down to every program the shell runs.
- MACs are compared in constant time.
- Fields are percent-encoded, so a command containing tabs or newlines can't forge extra fields or records.

**Threat model, honestly:** this is *tamper-evident*, not *tamper-proof*. Someone with write access can still
delete the whole file, and without a key they can rebuild a valid unkeyed chain. The defences are the HMAC key
(keep it somewhere the attacker can't read) and anchoring: periodically copy `audit head` somewhere off the
machine and check it with `--anchor`. Also, commands are logged in plaintext, so a password typed on the command
line ends up in the log. That's the same as shell history, and it's why the file is private.

### 2. `limit`: per-command resource sandbox

```sh
limit cpu=2 mem=256M fsize=10M files=32 nproc=64 -- ./untrusted-binary arg
limit cpu=5 -- python3 parse_input.py < suspicious.bin
```

The limits are applied with `setrlimit()` in the child, after `fork()` and before `exec()`, so only that
command (and anything it spawns) is constrained. The shell itself is never limited. Soft and hard limits are
both lowered so the program can't raise them again. When the kernel kills the process, vigil says why
(`CPU time limit exceeded`, `file size limit exceeded`) instead of a bare exit code.

| Resource | Kernel limit | Stops |
|---|---|---|
| `cpu=SEC` | `RLIMIT_CPU` | infinite loops, cryptominers (SIGXCPU, then SIGKILL 1 s later) |
| `mem=SIZE` | `RLIMIT_AS` | memory exhaustion (enforced on Linux; macOS ignores it) |
| `fsize=SIZE` | `RLIMIT_FSIZE` | filling the disk |
| `files=N` | `RLIMIT_NOFILE` | file-descriptor exhaustion |
| `nproc=N` | `RLIMIT_NPROC` | fork bombs |

This is a resource sandbox, not an isolation sandbox: it doesn't restrict file or network access. That would
need seccomp/namespaces on Linux or sandbox-exec on macOS.

### 3. No word-splitting, no globbing

In POSIX shells, an unquoted `$X` is split on spaces and glob-expanded, which causes a long tail of
real-world bugs (`rm $FILE` with `FILE="a b"`, or a crafted filename becoming extra arguments). vigil expands
every word to **exactly one argument**:

```
vigil$ X="a; echo PWNED"
vigil$ echo $X
a; echo PWNED
vigil$ X="*"; echo $X
*
```

Operators like `;` and `|` are recognised before expansion, so data coming from a variable can never become
shell syntax.

## How it works

```
input line ─► lexer ─► tokens ─► parser ─► command list (AST) ─► executor ─► audit log
             (quotes,           (pipelines,                     (expand words,
              operators)         &&, ||, ;, &,                   fork/exec, pipes,
                                 redirections)                   jobs, limits)
```

| File | What it does |
|---|---|
| `src/lexer.c` | Tokenizer; keeps raw words and expands them at run time (`expand_word`) so `export X=1; echo $X` works on one line |
| `src/parser.c` | Recursive-descent parser → list of pipelines joined by `;` `&&` `||` `&` |
| `src/exec.c` | `fork`/`execvp`, `pipe`/`dup2` plumbing, redirections, builtins with temporary fd redirection |
| `src/jobs.c` | Job table, `waitpid(WUNTRACED)`, process groups, terminal hand-off with `tcsetpgrp` |
| `src/limits.c` | `limit` parsing and `setrlimit` |
| `src/audit.c` | Hash-chained log, `flock`, `verify` / `tail` / `head` |
| `src/sha256.c` | SHA-256 + HMAC-SHA256 from scratch |
| `src/builtins.c` | `cd`, `export`, `fg`, `bg`, ... |

Operating-system concepts it exercises:

- **Process lifecycle:** `fork` → `execvp` → `waitpid`; exit vs. signal status (`128 + signo`).
- **IPC:** one `pipe()` per `|`, wired with `dup2`, with every unused end closed so readers see EOF.
- **Job control:** each pipeline gets its own process group (`setpgid` in both parent and child to avoid the
  race). The foreground group owns the terminal (`tcsetpgrp`), so Ctrl-C / Ctrl-Z reach the job and not the
  shell. The shell ignores `SIGTTOU`/`SIGTSTP` and resets signal dispositions in children before `exec`.
- **Builtins vs. children:** `cd` and `export` must run inside the shell process (a child's `chdir` dies with
  it), so they run in the parent with stdin/stdout/stderr saved and restored around any redirection.
- **Resource limits** inherited across `exec`, and **advisory file locking** for concurrent writers.

## Testing

- `tests/run_tests.sh`: 81 end-to-end tests covering quoting, expansion, operators, pipes, redirection,
  builtins, syntax errors, background jobs, every `limit` resource, and audit-log tampering (edit, delete,
  truncate, wrong key, symlink attack, file permissions).
- `tests/test_sha256.c`: FIPS 180-4 and RFC 4231 known-answer vectors, including a 1,000,000-byte input fed
  in uneven chunks.
- `fuzz/fuzz_parser.c`: libFuzzer harness over the lexer, parser and expander (1.4M+ executions, no crashes).
- CI: Linux + macOS builds with `-Werror`, ASan/UBSan test run, and a 2-minute fuzzing job on every push.

## Limitations / future work

- No globbing (`*.c`), subshells `( )`, command substitution `$(...)`, here-docs or control flow
  (`if`/`for`). Scripts are line-by-line commands.
- No line editing or history recall (no readline dependency, on purpose).
- Ideas: ship the audit head to a remote syslog server for automatic anchoring; `limit net=off` using
  namespaces/seccomp on Linux; `$(...)` and globbing that preserve the no-injection guarantee.

## License

MIT
