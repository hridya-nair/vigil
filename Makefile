CC      ?= cc
CFLAGS  ?= -O2 -g
# Project flags live in their own variable so `make CFLAGS=...` adds to them
# instead of silently replacing them.
WARN    := -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 \
           -D_DEFAULT_SOURCE -D_DARWIN_C_SOURCE
ALL_CFLAGS = $(WARN) $(CFLAGS)
SAN     := -fsanitize=address,undefined -fno-omit-frame-pointer

SRC     := src/main.c src/lexer.c src/parser.c src/exec.c src/builtins.c \
           src/jobs.c src/limits.c src/audit.c src/sha256.c src/util.c
LIB_SRC := $(filter-out src/main.c,$(SRC))

.PHONY: all clean test test-asan fuzz

all: vigil

vigil: $(SRC) src/shell.h src/sha256.h
	$(CC) $(ALL_CFLAGS) -o $@ $(SRC)

vigil-asan: $(SRC) src/shell.h src/sha256.h
	$(CC) $(ALL_CFLAGS) $(SAN) -o $@ $(SRC)

tests/test_sha256: tests/test_sha256.c src/sha256.c src/sha256.h
	$(CC) $(ALL_CFLAGS) -Isrc -o $@ tests/test_sha256.c src/sha256.c

test: vigil tests/test_sha256
	./tests/test_sha256
	./tests/run_tests.sh ./vigil

test-asan: vigil-asan tests/test_sha256
	./tests/test_sha256
	ASAN_OPTIONS=detect_leaks=1 ./tests/run_tests.sh ./vigil-asan

# Needs clang with libFuzzer (Linux). Runs for FUZZ_SECONDS.
FUZZ_SECONDS ?= 60
fuzz/fuzz_parser: fuzz/fuzz_parser.c $(LIB_SRC)
	clang -std=c11 -g -O1 -D_DEFAULT_SOURCE -fsanitize=fuzzer,address,undefined \
	      -Isrc -o $@ fuzz/fuzz_parser.c $(LIB_SRC)

fuzz: fuzz/fuzz_parser
	mkdir -p fuzz/corpus && cp fuzz/seeds/* fuzz/corpus/
	./fuzz/fuzz_parser -max_total_time=$(FUZZ_SECONDS) -max_len=512 fuzz/corpus

clean:
	rm -rf vigil vigil-asan tests/test_sha256 fuzz/fuzz_parser fuzz/corpus *.dSYM
