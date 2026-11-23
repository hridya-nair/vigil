/* libFuzzer harness: throws arbitrary bytes at the lexer, parser and word
 * expander. Built with ASan + UBSan, so any out-of-bounds access, leak or
 * undefined behaviour in the input-handling code is a crash.
 *
 *   make fuzz FUZZ_SECONDS=300
 */
#include "shell.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *in = malloc(size + 1);
    if (!in) return 0;
    memcpy(in, data, size);
    in[size] = '\0';

    token_list tl;
    const char *err;
    if (lex(in, &tl, &err) == 0) {
        command_list cl;
        if (parse(&tl, &cl, &err) == 0) {
            for (int i = 0; i < cl.nitems; i++) {
                pipeline *pl = &cl.items[i].pl;
                for (int j = 0; j < pl->ncmds; j++) {
                    command *c = &pl->cmds[j];
                    for (int k = 0; k < c->argc; k++) {
                        char *w = expand_word(c->argv[k], &err);
                        free(w);
                    }
                }
                char *s = pipeline_to_string(pl);
                free(s);
            }
            command_list_free(&cl);
        }
        token_list_free(&tl);
    }
    free(in);
    return 0;
}
