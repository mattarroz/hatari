//
// Created by matze on 28.07.24.
//

#ifndef _GDB_ARCH_H_
#define _GDB_ARCH_H_

#include <stddef.h>
#include <stdint.h>


enum regs {
  D0,
  D1,
  D2,
  D3,
  D4,
  D5,
  D6,
  D7,
  A0,
  A1,
  A2,
  A3,
  A4,
  A5,
  PS,
  PC,
  FP,
  SP,
  GDB_NUM_REGS
};

/* required structure */
struct gdb_ctx {
  /* cause of the exception */
  unsigned int exception;
  unsigned int registers[GDB_NUM_REGS];
};

void arch_gdb_continue(void);
void arch_gdb_step(void);
size_t arch_gdb_reg_readall(struct gdb_ctx *p_ctx, uint8_t *buf, size_t buflen);
size_t arch_gdb_reg_writeall(struct gdb_ctx *p_ctx, uint8_t *string, size_t i);
size_t arch_gdb_reg_readone(struct gdb_ctx *p_ctx, uint8_t *buf, size_t i,
                            uintptr_t addr);
size_t arch_gdb_reg_writeone(struct gdb_ctx *p_ctx, uint8_t *string,
                             size_t strlen, uintptr_t addr);
int arch_gdb_add_breakpoint(struct gdb_ctx *ctx, uint8_t type,
                            uintptr_t addr, uint32_t kind);
int arch_gdb_remove_breakpoint(struct gdb_ctx *ctx, uint8_t type,
                               uintptr_t addr, uint32_t kind);
int arch_gdb_mem_read(uint8_t *buf, size_t buf_len, uintptr_t addr,
                      size_t len);
int arch_gdb_mem_write(const uint8_t *buf, uintptr_t addr, size_t len);
void arch_gdb_init(void);

void z_gdb_entry(void);

#endif //_GDB_ARCH_H_
