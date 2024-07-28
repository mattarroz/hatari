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

/* Required struct */
static struct gdb_ctx ctx;
#define DEBUG_BUFFER_SIZE 1024
static char debug_buffer[DEBUG_BUFFER_SIZE];
static regex_t regex, regex_pc;

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

  if (regexec (&regex_pc, p, 3, matches, 0))
    fprintf(stderr, "gdb_arch_get_registers_from_string: Could not extract PC\n");
  registers[i].name[0] = 'P';
  registers[i].name[1] = 'C';
  registers[i].name[2] = '\0';
  int len = matches[1].rm_eo - matches[1].rm_so;
  strncpy(registers[i].value, p + matches[1].rm_so, len);
  registers[i].value[len] = '\0';

  // Print the extracted values
  for (int j = 0; j < NUM_REGISTERS; j++) {
    printf("Register %s: %s\n", registers[j].name, registers[j].value);
  }
  size_t c = 0;
  for (size_t j = 0; j < NUM_REGISTERS; j++) {
    if (strcmp(registers[j].name, "SR") == 0) {
      strncpy(registers[j].value + 4, "0000", 4);
    }

    const size_t regval_len = strlen(registers[j].value);
    strncpy(&output[c], registers[j].value, regval_len);
    c += regval_len;
  }

  assert(c == NUM_REGISTERS*8);
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
      cpucmds[i].pFunction(1, NULL);
      const size_t reglen = gdb_arch_get_registers_from_string(debug_buffer, buf);
      if (reglen == 0) {
        return 0;
      }
      memset(buf+reglen, 'x', buflen-reglen);

      return 18*8+8*8*3+3*8;
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
                            uintptr_t addr, uint32_t kind)
{
  return -2;
}


int arch_gdb_remove_breakpoint(struct gdb_ctx *ctx, uint8_t type,
                               uintptr_t addr, uint32_t kind)
{
  return -2;
}

/* Read memory byte-by-byte */
static inline int gdb_mem_read_unaligned(uint8_t *buf, size_t buf_len,
                                         uintptr_t addr, size_t len)
{
  uint8_t data;
  size_t pos, count = 0;

  /* Read from system memory */
  for (pos = 0; pos < len; pos++) {
    data = *(uint8_t *)(addr + pos);
    count += gdb_bin2hex(&data, 1, buf + count, buf_len - count);
  }

  return count;
}

/* Read memory with alignment constraint */
static inline int gdb_mem_read_aligned(uint8_t *buf, size_t buf_len,
                                       uintptr_t addr, size_t len,
                                       uint8_t align)
{
  /*
        * Memory bus cannot do byte-by-byte access and
        * each access must be aligned.
   */
  size_t read_sz, pos;
  size_t remaining = len;
  uint8_t *mem_ptr;
  size_t count = 0;
  int ret;

  union {
    uint32_t u32;
    uint8_t b8[4];
  } data;

  /* Max alignment */
  if (align > 4) {
    ret = -1;
    goto out;
  }

  /* Round down according to alignment. */
  mem_ptr = UINT_TO_POINTER(ROUND_DOWN(addr, align));

  /*
        * Figure out how many bytes to skip (pos) and how many
        * bytes to read at the beginning of aligned memory access.
   */
  pos = addr & (align - 1);
  read_sz = MIN(len, align - pos);

  /* Loop till there is nothing more to read. */
  while (remaining > 0) {
    data.u32 = *(uint32_t *)mem_ptr;

    /*
                * Read read_sz bytes from memory and
                * convert the binary data into hexadecimal.
     */
    count += gdb_bin2hex(&data.b8[pos], read_sz,
                         buf + count, buf_len - count);

    remaining -= read_sz;
    if (remaining > align) {
      read_sz = align;
    } else {
      read_sz = remaining;
    }

    /* Read the next aligned datum. */
    mem_ptr += align;

    /*
                * Any memory accesses after the first one are
                * aligned by design. So there is no need to skip
                * any bytes.
     */
    pos = 0;
  };

  ret = count;

out:
  return ret;
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

  if (!gdb_mem_can_read(addr, len, &align)) {
    ret = -1;
    goto out;
  }

  if (align > 1) {
    ret = gdb_mem_read_aligned(buf, buf_len,
                               addr, len,
                               align);
  } else {
    ret = gdb_mem_read_unaligned(buf, buf_len,
                                 addr, len);
  }

out:
  return ret;
}

/* Write memory byte-by-byte */
static int gdb_mem_write_unaligned(const uint8_t *buf, uintptr_t addr,
                                   size_t len)
{
  uint8_t data;
  int ret;
  size_t count = 0;

  while (len > 0) {
    size_t cnt = hex2bin(buf, 2, &data, sizeof(data));

    if (cnt == 0) {
      ret = -1;
      goto out;
    }

    *(uint8_t *)addr = data;

    count += cnt;
    addr++;
    buf += 2;
    len--;
  }

  ret = count;

out:
  return ret;
}

/* Write memory with alignment constraint */
static int gdb_mem_write_aligned(const uint8_t *buf, uintptr_t addr,
                                 size_t len, uint8_t align)
{
  size_t pos, write_sz;
  uint8_t *mem_ptr;
  size_t count = 0;
  int ret;

  /*
        * Incoming buf is of hexadecimal characters,
        * so binary data size is half of that.
   */
  size_t remaining = len;

  union {
    uint32_t u32;
    uint8_t b8[4];
  } data;

  /* Max alignment */
  if (align > 4) {
    ret = -1;
    goto out;
  }

  /*
        * Round down according to alignment.
        * Read the data (of aligned size) first
        * as we need to do read-modify-write.
   */
  mem_ptr = UINT_TO_POINTER(ROUND_DOWN(addr, align));
  data.u32 = *(uint32_t *)mem_ptr;

  /*
        * Figure out how many bytes to skip (pos) and how many
        * bytes to write at the beginning of aligned memory access.
   */
  pos = addr & (align - 1);
  write_sz = MIN(len, align - pos);

  /* Loop till there is nothing more to write. */
  while (remaining > 0) {
    /*
                * Write write_sz bytes from memory and
                * convert the binary data into hexadecimal.
     */
    size_t cnt = hex2bin(buf, write_sz * 2,
                         &data.b8[pos], write_sz);

    if (cnt == 0) {
      ret = -1;
      goto out;
    }

    count += cnt;
    buf += write_sz * 2;

    remaining -= write_sz;
    if (remaining > align) {
      write_sz = align;
    } else {
      write_sz = remaining;
    }

    /* Write data to memory */
    *(uint32_t *)mem_ptr = data.u32;

    /* Point to the next aligned datum. */
    mem_ptr += align;

    if (write_sz != align) {
      /*
                        * Since we are not writing a full aligned datum,
                        * we need to do read-modify-write. Hence reading
                        * it here before the next hex2bin() call.
       */
      data.u32 = *(uint32_t *)mem_ptr;
    }

    /*
                * Any memory accesses after the first one are
                * aligned by design. So there is no need to skip
                * any bytes.
     */
    pos = 0;
  };

  ret = count;

out:
  return ret;
}

/**
* Write data to a given memory address and length.
*
* @return Number of bytes written to memory, or -1 if error
 */
int arch_gdb_mem_write(const uint8_t *buf, uintptr_t addr, size_t len) {
  uint8_t align;
  int ret;

  if (!gdb_mem_can_write(addr, len, &align)) {
    ret = -1;
    goto out;
  }

  if (align > 1) {
    ret = gdb_mem_write_aligned(buf, addr, len, align);
  } else {
    ret = gdb_mem_write_unaligned(buf, addr, len);
  }

out:
  return ret;
}

void arch_gdb_init(void) {
  debugOutput = fmemopen(debug_buffer, DEBUG_BUFFER_SIZE, "w+");
  n_cpucmds = DebugCpu_Init(&cpucmds);

  int reti = regcomp(&regex,
                     "\\b([DA][0-7]|SR)\\s*[=:]?\\s*([0-9A-Fa-f]{4,8})\\b",
                     REG_EXTENDED);
  int retpc = regcomp(&regex_pc, "\n([0-9A-Fa-f]{8}).*\nNext PC", REG_EXTENDED);
  if (reti || retpc) {
    fprintf(stderr, "arch_gdb_init: Could not compile regex\n");
    return;
  }


}

void z_gdb_entry(void) {
  z_gdb_main_loop(&ctx);
}
