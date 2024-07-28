//
// Created by matze on 28.07.24.
//

#include "debugcpu.h"
#include "debug_priv.h"

#include "gdb_arch.h"

void arch_gdb_continue(void) {}
void arch_gdb_step(void) {
//    DebugCpu_Step
}
size_t arch_gdb_reg_readall(struct gdb_ctx *p_ctx, uint8_t buf[257], size_t i) {

  return 0;
}
size_t arch_gdb_reg_writeall(struct gdb_ctx *p_ctx, uint8_t *string, size_t i) {
  return 0;
}
size_t arch_gdb_reg_readone(struct gdb_ctx *p_ctx, uint8_t buf[257], size_t i,
                            uintptr_t addr) {
  return 0;
}
size_t arch_gdb_reg_writeone(struct gdb_ctx *p_ctx, uint8_t *string,
                             size_t strlen, uintptr_t addr) {
  return 0;
}
void arch_gdb_init(void) {
  const dbgcommand_t *cpucmd = NULL;
  int cpucmds = DebugCpu_Init(&cpucmd);
}
