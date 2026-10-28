/*
 * Copyright 2026 Revetware LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "argon2.h"

static int nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t decode(const char *hex, uint8_t *out, size_t maximum) {
    size_t i, length = strlen(hex);
    if ((length & 1) || length / 2 > maximum) exit(2);
    for (i = 0; i < length / 2; i++) {
        int hi = nibble(hex[2 * i]), lo = nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) exit(2);
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return length / 2;
}

int main(int argc, char **argv) {
    FILE *in;
    char line[4096];
    int cases = 0;
    if (argc != 2 || !(in = fopen(argv[1], "r"))) return 2;
    puts("# Argon2id v19 raw tags regenerated with reference C 20190702, pinned OCI compiler image");
    puts("# memoryKiB<TAB>passes<TAB>lanes<TAB>tagBytes<TAB>passwordUtf8Hex<TAB>saltHex<TAB>tagHex");
    while (fgets(line, sizeof(line), in)) {
        char *field[7], *cursor;
        uint8_t pwd[4096], salt[64], out[64];
        size_t pwdlen, saltlen;
        unsigned long memory, passes, lanes, taglen;
        argon2_context context;
        int i, error;
        if (line[0] == '#') continue;
        cursor = strtok(line, "\t\r\n");
        for (i = 0; i < 7; i++) {
            if (!cursor) return 3;
            field[i] = cursor;
            cursor = strtok(NULL, "\t\r\n");
        }
        if (cursor) return 3;
        memory = strtoul(field[0], NULL, 10);
        passes = strtoul(field[1], NULL, 10);
        lanes = strtoul(field[2], NULL, 10);
        taglen = strtoul(field[3], NULL, 10);
        if (taglen < 16 || taglen > 64) return 3;
        pwdlen = decode(field[4], pwd, sizeof(pwd));
        saltlen = decode(field[5], salt, sizeof(salt));
        memset(&context, 0, sizeof(context));
        context.out = out; context.outlen = (uint32_t)taglen;
        context.pwd = pwd; context.pwdlen = (uint32_t)pwdlen;
        context.salt = salt; context.saltlen = (uint32_t)saltlen;
        context.m_cost = (uint32_t)memory; context.t_cost = (uint32_t)passes;
        context.lanes = (uint32_t)lanes; context.threads = 1;
        context.version = ARGON2_VERSION_13;
        context.flags = ARGON2_DEFAULT_FLAGS;
        error = argon2_ctx(&context, Argon2_id);
        if (error != ARGON2_OK) {
            fprintf(stderr, "reference C error: %s\n", argon2_error_message(error));
            return 4;
        }
        printf("%s\t%s\t%s\t%s\t%s\t%s\t", field[0], field[1], field[2],
               field[3], field[4], field[5]);
        for (i = 0; i < (int)taglen; i++) printf("%02x", out[i]);
        putchar('\n');
        cases++;
        memset(pwd, 0, sizeof(pwd)); memset(salt, 0, sizeof(salt));
        memset(out, 0, sizeof(out));
    }
    fclose(in);
    if (cases != 9) return 5;
    return 0;
}
