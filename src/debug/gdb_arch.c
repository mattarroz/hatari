//
// Created by matze on 28.07.24.
//

#include "debug_priv.h"
#include "debugcpu.h"
#include <assert.h>
#include <malloc.h>
#include <regex.h>
#include <string.h>

#include "gdb_arch.h"
#include "gdbstub.h"
#include "m68000.h"

/* Required struct */
static struct gdb_ctx ctx;
#define DEBUG_BUFFER_SIZE 1024
static char debug_buffer[DEBUG_BUFFER_SIZE];
static regex_t regex, regex_pc, regex_memdump;

const dbgcommand_t *cpucmds;
size_t n_cpucmds = 0;


static size_t gdb_arch_get_registers_from_string(const char *input,
                                                 char *output) {
    const char *p = input;
    int i = 0;
    regmatch_t matches[3];
#define NUM_REGISTERS 18

    typedef struct {
        char name[10];
        char value[9];
    } Register;

    Register registers[NUM_REGISTERS];

    while (!regexec(&regex, p, 3, matches, 0)) {
        // Extract register name
        int len = matches[1].rm_eo - matches[1].rm_so;
        strncpy(registers[i].name, p + matches[1].rm_so, len);
        registers[i].name[len] = '\0';

        // Extract register value
        len = matches[2].rm_eo - matches[2].rm_so;
        strncpy(registers[i].value, p + matches[2].rm_so, len);
        registers[i].value[len] = '\0';

        p += matches[0].rm_eo;
        i++;
    }

    if (regexec(&regex_pc, p, 3, matches, 0))
        fprintf(stderr, "gdb_arch_get_registers_from_string: Could not extract PC\n");
    registers[i].name[0] = 'P';
    registers[i].name[1] = 'C';
    registers[i].name[2] = '\0';
    int len = matches[1].rm_eo - matches[1].rm_so;
    strncpy(registers[i].value, p + matches[1].rm_so, len);
    registers[i].value[len] = '\0';

    size_t c = 0;
    for (size_t j = 0; j < NUM_REGISTERS; j++) {
        if (strcmp(registers[j].name, "SR") == 0) {
            strncpy(registers[j].value + 4, "0000", 5);
        }

        const size_t regval_len = strlen(registers[j].value);
        strncpy(&output[c], registers[j].value, regval_len);
        assert(regval_len == 8);
        c += regval_len;
    }

    assert(c == NUM_REGISTERS * 8);
    return c;
}

void arch_gdb_continue(void) {
    for (size_t i = 0; i < n_cpucmds; i++) {
        if (cpucmds[i].sShortName && *cpucmds[i].sShortName == 'c') {
            cpucmds[i].pFunction(0, NULL);
            return;
        }
    }
}

void arch_gdb_step(void) {
    for (size_t i = 0; i < n_cpucmds; i++) {
        if (cpucmds[i].sShortName && *cpucmds[i].sShortName == 's') {
            cpucmds[i].pFunction(0, NULL);
            return;
        }
    }
}

size_t arch_gdb_reg_readall(struct gdb_ctx *p_ctx, uint8_t *buf, size_t buflen) {
    for (size_t i = 0; i < n_cpucmds; i++) {
        if (cpucmds[i].sShortName && *cpucmds[i].sShortName == 'r') {
            rewind(debugOutput);
            cpucmds[i].pFunction(1, NULL);
            fwrite("\0", 1, 1, debugOutput);
            fflush(debugOutput);
            const size_t reglen = gdb_arch_get_registers_from_string(debug_buffer, buf);
            memset(buf + reglen, 'x', buflen - reglen);

            return 18 * 8 + 8 * 8 * 3 + 3 * 8;
        }
    }
    return 0;
}

size_t arch_gdb_reg_writeall(struct gdb_ctx *p_ctx, uint8_t *string, size_t i) {
    // TODO
    return 0;
}

size_t arch_gdb_reg_readone(struct gdb_ctx *p_ctx, uint8_t *buf, size_t i,
                            uintptr_t addr) {
    // TODO
    return 0;
}

size_t arch_gdb_reg_writeone(struct gdb_ctx *p_ctx, uint8_t *string,
                             size_t strlen, uintptr_t addr) {
    // TODO
    return 0;
}

int arch_gdb_add_breakpoint(struct gdb_ctx *ctx, uint8_t type,
                            uintptr_t addr, uint32_t kind) {
    for (size_t i = 0; i < n_cpucmds; i++) {
        if (cpucmds[i].sShortName && *cpucmds[i].sShortName == 'b') {
            char *argv[2];
            char buf[256];

            snprintf(buf, 256, "pc=0x%lx", addr);
            argv[1] = buf;
            printf("arch_gdb_add_breakpoint: %s\n", argv[1]);
            cpucmds[i].pFunction(2, (char **) argv);
            M68000_SetSpecial(SPCFLAG_DEBUGGER);
            return 0;
        }
    }
    return -2;
}


int arch_gdb_remove_breakpoint(struct gdb_ctx *ctx, uint8_t type,
                               uintptr_t addr, uint32_t kind) {
    return -2;
}


static int gdb_arch_get_memdump_from_string(char input[1024], uint8_t *output, size_t len) {
    regmatch_t matches[1];
    char *p_input = input;
    char *p_output = output;
    size_t bytes_matched = 0;

    printf("input is %s\n", input);
    while (!regexec(&regex_memdump, p_input, 1, matches, 0)) {
        const int start = matches[0].rm_so;
        const int end = matches[0].rm_eo;
        const int byte_len = end - start;
        memcpy(p_output, p_input + start, byte_len);

        bytes_matched++;
        if (bytes_matched > len) {
            fprintf(stderr,
                    "gdb_arch_get_memdump_from_string: fatal error, we received more bytes (%d) than we should have (%d).\n",
                    bytes_matched, len);
        }
        p_input += end;
        p_output += byte_len;
    }
    p_output[0] = '\0';

    return strlen(output);
}

/**
* Read data from a given memory address and length.
*
* @return Number of bytes read from memory, or -1 if error
 */
int arch_gdb_mem_read(uint8_t *buf, size_t buf_len, uintptr_t addr,
                      size_t len) {
    uint8_t align;
    int ret;

  /*
        * Make sure there is enough space in the output
        * buffer for hexadecimal representation.
   */
    if ((len * 2) > buf_len) {
        ret = -1;
        goto out;
    }

    for (size_t i = 0; i < n_cpucmds; i++) {
        if (cpucmds[i].sShortName && *cpucmds[i].sShortName == 'm') {
            char *argv[4];
            char addr_str[256];
            char len_str[256];
            if (align > 1) {
                // ??
            }
            char mode_str[] = "b";

            argv[1] = mode_str;
            snprintf(addr_str, 256, "0x%lx", addr);
            argv[2] = addr_str;
            snprintf(len_str, 256, "%ld", len);
            argv[3] = len_str;

            printf("arch_gdb_mem_read: %s bytes from %s\n", argv[3], argv[2]);
            rewind(debugOutput);
            cpucmds[i].pFunction(4, (char **) argv);
            fwrite("\0", 1, 1, debugOutput);
            fflush(debugOutput);
            printf("arch_gdb_mem_read: %s\n", debug_buffer);
        }
    }

    ret = gdb_arch_get_memdump_from_string(debug_buffer, buf, buf_len);

    out:
    return ret;
}


/**
* Write data to a given memory address and length.
*
* @return Number of bytes written to memory, or -1 if error
 */
int arch_gdb_mem_write(const uint8_t *buf, uintptr_t addr, size_t len) {
// TODO
    return 0;
}

void arch_gdb_init(void) {
    debugOutput = fmemopen(debug_buffer, DEBUG_BUFFER_SIZE, "w");
    n_cpucmds = DebugCpu_Init(&cpucmds);

    // FIXME(mreis): move to static init section
    int ret = regcomp(&regex,
                      "\\b([DA][0-7]|SR)\\s*[=:]?\\s*([0-9A-Fa-f]{4,8})\\b",
                      REG_EXTENDED);
    ret |= regcomp(&regex_pc, "\n([0-9A-Fa-f]{8}).*\nNext PC", REG_EXTENDED);

    ret |= regcomp(&regex_memdump, "\\b([0-9a-fA-F]{2})\\b", REG_EXTENDED);
    if (ret) {
        fprintf(stderr, "arch_gdb_init: Could not compile regex\n");
        return;
    }
}

void z_gdb_entry(void) {
    arch_gdb_init();
    z_gdb_main_loop(&ctx);
}
