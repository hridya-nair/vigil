#!/bin/sh
# Integration tests: run vigil -c '...' and compare output / exit status.
# usage: tests/run_tests.sh ./vigil

VIGIL=${1:-./vigil}
case "$VIGIL" in /*) ;; *) VIGIL="$PWD/$VIGIL" ;; esac

# pwd -P: on macOS mktemp gives /var/... but getcwd() reports /private/var/...
TMP=$(cd "$(mktemp -d)" && pwd -P)
trap 'rm -rf "$TMP"' EXIT
export VIGIL_AUDIT_FILE="$TMP/audit.log"
unset VIGIL_AUDIT VIGIL_AUDIT_KEY

pass=0
fail=0

# expect NAME EXPECTED_OUTPUT COMMAND
expect() {
    name=$1 want=$2 cmd=$3
    got=$(cd "$TMP" && "$VIGIL" -c "$cmd" 2>&1)
    if [ "$got" = "$want" ]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        printf 'FAIL %s\n  cmd:  %s\n  want: %s\n  got:  %s\n' "$name" "$cmd" "$want" "$got"
    fi
}

# expect_status NAME EXPECTED_STATUS COMMAND
expect_status() {
    name=$1 want=$2 cmd=$3
    (cd "$TMP" && "$VIGIL" -c "$cmd" >/dev/null 2>&1)
    got=$?
    if [ "$got" = "$want" ]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        printf 'FAIL %s\n  cmd:  %s\n  want status %s, got %s\n' "$name" "$cmd" "$want" "$got"
    fi
}

# ---------------------------------------------------------------- basics
expect "simple command"       "hello"                 'echo hello'
expect "multiple args"        "a b c"                 'echo a   b    c'
expect "comment"              "x"                     'echo x # ignored'
expect "not found message"    "vigil: nosuchcmd_xyz: command not found" 'nosuchcmd_xyz'
expect_status "not found 127" 127                     'nosuchcmd_xyz'
expect_status "exit code"     7                       'exit 7'
expect_status "exit wraps"    1                       'exit 257'
expect_status "true"          0                       'true'
expect_status "false"         1                       'false'

# ---------------------------------------------------------------- quoting
expect "single quotes"        'a $HOME b'             "echo 'a \$HOME b'"
expect "double quotes"        "a  b"                  'echo "a  b"'
expect "escaped space"        "a b"                   'echo a\ b'
expect "escaped dollar"       '$HOME'                 'echo \$HOME'
expect "empty quoted arg"     "1"                     'printf "%s\n" "" | wc -l | tr -d " "'
expect "adjacent quotes"      "abcd"                  "echo a'b'\"c\"d"
expect "quote in quotes"      'say "hi"'              'echo "say \"hi\""'

# ---------------------------------------------------------------- expansion
expect "var"                  "/root-x"               'HOME=/root; echo $HOME-x'
expect "braces"               "foobar"                'export V=foo; echo ${V}bar'
expect "status var"           "1"                     'false; echo $?'
expect "unset var dropped"    "a b"                   'echo a $NOPE_NOT_SET b'
expect "tilde"                "/home/t/docs"          'HOME=/home/t; echo ~/docs'
expect "tilde mid-word"       "a~b"                   'echo a~b'
expect "same-line export"     "42"                    'export N=42; echo $N'
expect "assignment"           "v"                     'Z=v; echo $Z'
expect "no word splitting"    "1"                     'X="a b c"; printf "%s\n" $X | wc -l | tr -d " "'
expect "no injection"         'a; echo PWNED'         'X="a; echo PWNED"; echo $X'
expect "no globbing"          '*'                     'X="*"; echo $X'
expect_status "bad subst"     2                       'echo ${1bad}'

# ---------------------------------------------------------------- operators
expect "and true"             "yes"                   'true && echo yes'
expect "and false"            ""                      'false && echo yes'
expect "or"                   "fallback"              'false || echo fallback'
expect "and-or chain"         "b"                     'false && echo a || echo b'
expect "sequence"             "1
2"                                                    'echo 1; echo 2'
expect_status "last status"   1                       'true; false'

# ---------------------------------------------------------------- pipes
expect "pipe"                 "HELLO"                 'echo hello | tr a-z A-Z'
expect "long pipe"            "3"                     'printf "a\nb\nc\n" | cat | cat | wc -l | tr -d " "'
expect_status "pipe status"   1                       'echo x | false'
expect "builtin in pipe"      "$TMP"                  'pwd | cat'

# ---------------------------------------------------------------- redirection
expect "out redirect"         "data"                  'echo data > f1; cat f1'
expect "append"               "1
2"                                                    'echo 1 > f2; echo 2 >> f2; cat f2'
expect "truncate"             "new"                   'echo old > f3; echo new > f3; cat f3'
expect "in redirect"          "3"                     'printf "a\nb\nc\n" > f4; wc -l < f4 | tr -d " "'
expect "stderr redirect"      ""                      'ls /no/such/dir 2> f5'
expect "stderr to stdout"     "1"                     'ls /no/such/dir 2>&1 | wc -l | tr -d " "'
expect "redirect expansion"   "ok"                    'F=f6; echo ok > $F; cat f6'
expect "builtin redirect"     "$TMP"                  'pwd > f7; cat f7'
expect "missing input file"   "vigil: nofile: No such file or directory" 'cat < nofile'

# ---------------------------------------------------------------- builtins
expect "cd"                   "/"                     'cd /; pwd'
expect "cd dash"              "$TMP"                  'cd /; cd -'
expect "cd error"             "cd: /no/such: No such file or directory" 'cd /no/such'
expect "unset"                "x"                     'export Q=1; unset Q; echo x$Q'
expect "export invalid"       "export: '1x=2': not a valid identifier" 'export 1x=2'

# ---------------------------------------------------------------- syntax errors
expect "unterminated quote"   "vigil: syntax error: unterminated double quote" 'echo "abc'
expect "leading pipe"         "vigil: syntax error: missing command" '| echo'
expect "dangling and"         "vigil: syntax error: expected a command after '&&'" 'echo a &&'
expect "redirect no file"     "vigil: syntax error: expected a file name after redirection" 'echo >'
expect_status "syntax status" 2                       'echo "abc'

# ---------------------------------------------------------------- background
expect "background job"       "fg-first
bg-done"                                              'sh -c "sleep 0.3; echo bg-done" & echo fg-first; sleep 0.6'

# ---------------------------------------------------------------- limit
expect "limit cpu"            "vigil: CPU time limit exceeded" 'limit cpu=1 -- sh -c "while :; do :; done"'
expect_status "limit cpu st"  152                     'limit cpu=1 -- sh -c "while :; do :; done"'
expect_status "limit fsize"   153                     'limit fsize=1K -- head -c 100000 /dev/zero > big'
expect "limit files"          "8"                     'limit files=8 -- sh -c "ulimit -n"'
expect "limit is per-command" "$(ulimit -n)"          'limit files=8 -- true; sh -c "ulimit -n"'
expect "limit bad key"        "vigil: limit: unknown resource 'bogus' (use cpu, mem, fsize, files, nproc)" 'limit bogus=1 -- ls'
expect_status "limit bad val" 2                       'limit cpu=abc -- ls'
expect "limit in pipe"        "ok"                    'echo ok | limit cpu=5 -- cat'
if [ "$(uname)" = "Linux" ]; then
    expect_status "limit mem" 1 'limit mem=64M -- python3 -c "x = bytearray(512*1024*1024)"'
fi

# ---------------------------------------------------------------- audit log
rm -f "$VIGIL_AUDIT_FILE"
"$VIGIL" -c 'echo one' >/dev/null
"$VIGIL" -c 'echo two | cat' >/dev/null
"$VIGIL" -c 'false' >/dev/null
expect "audit verify ok"      "audit: OK  3 records, chain intact" 'audit verify | head -1'
expect "audit tail"           "echo two | cat"        'audit tail 4 | sed -n 2p | sed "s/.*]  //"'
expect "audit records status" "[  1]"                 'audit tail 5 | sed -n 3p | grep -o "\[  1\]"'

# Tamper: change a command in the middle of the log.
cp "$VIGIL_AUDIT_FILE" "$TMP/good.log"
sed 's/echo two/echo TWO/' "$TMP/good.log" > "$VIGIL_AUDIT_FILE"
expect_status "tamper edit"   1                       'audit verify'

# Tamper: delete a record.
sed '2d' "$TMP/good.log" > "$VIGIL_AUDIT_FILE"
expect_status "tamper delete" 1                       'audit verify'

# Tamper: truncate the end, detected with an anchor.
cp "$TMP/good.log" "$VIGIL_AUDIT_FILE"
HEAD=$(tail -1 "$TMP/good.log" | awk -F'\t' '{print $9}')
head -2 "$TMP/good.log" > "$VIGIL_AUDIT_FILE"
expect_status "tamper truncate" 1                     "audit verify --anchor $HEAD"
cp "$TMP/good.log" "$VIGIL_AUDIT_FILE"
expect_status "anchor ok"     0                       "audit verify --anchor $HEAD"

# Keyed log: the key is hidden from children and the HMAC chain verifies.
rm -f "$VIGIL_AUDIT_FILE"
got=$(cd "$TMP" && VIGIL_AUDIT_KEY=s3cret "$VIGIL" -c 'echo "key=[$VIGIL_AUDIT_KEY]"; env | grep -c VIGIL_AUDIT_KEY')
if [ "$got" = "key=[]
0" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL key hidden from children: $got"; fi
if (cd "$TMP" && VIGIL_AUDIT_KEY=s3cret "$VIGIL" -c 'audit verify' >/dev/null 2>&1); then
    pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL keyed verify"; fi
if (cd "$TMP" && VIGIL_AUDIT_KEY=wrong "$VIGIL" -c 'audit verify' >/dev/null 2>&1); then
    fail=$((fail + 1)); echo "FAIL wrong key should not verify"; else pass=$((pass + 1)); fi

# Audit file must be private and never followed through a symlink.
rm -f "$VIGIL_AUDIT_FILE"
"$VIGIL" -c 'true'
perms=$(ls -l "$VIGIL_AUDIT_FILE" | cut -c1-10)
if [ "$perms" = "-rw-------" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL audit perms: $perms"; fi
rm -f "$VIGIL_AUDIT_FILE"
ln -s "$TMP/victim" "$VIGIL_AUDIT_FILE"
"$VIGIL" -c 'true' 2>/dev/null
if [ ! -e "$TMP/victim" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL followed symlink"; fi
rm -f "$VIGIL_AUDIT_FILE"

# ---------------------------------------------------------------- scripts
printf 'echo from script\nexit 3\necho never\n' > "$TMP/s.vsh"
got=$("$VIGIL" "$TMP/s.vsh"); st=$?
if [ "$got" = "from script" ] && [ $st -eq 3 ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL script mode: $got ($st)"; fi

got=$(printf 'echo piped\nfalse\n' | "$VIGIL"); st=$?
if [ "$got" = "piped" ] && [ $st -eq 1 ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL stdin mode: $got ($st)"; fi

echo
echo "passed: $pass  failed: $fail"
[ "$fail" -eq 0 ]
