/*
* Copyright (c) 2020 Intel Corporation.
*
* SPDX-License-Identifier: Apache-2.0
*/


#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "gdb_arch.h"
#include "gdbstub.h"
#include "gdbstub_backend.h"
#include "configuration.h"
#include "main.h"

/* +1 is for the NULL character added during receive */
// FIXME: this is essentially the hex value of the registers
#define GDB_PACKET_SIZE     (18*8+96*8+3*8 + 1)

/* GDB remote serial protocol does not define errors value properly
* and handle all error packets as the same the code error is not
* used. There are informal values used by others gdbstub
* implementation, like qemu. Lets use the same here.
*/
#define GDB_ERROR_GENERAL   "E01"
#define GDB_ERROR_MEMORY    "E14"
#define GDB_ERROR_OVERFLOW  "E22"

static bool not_first_start;

/* Empty memory region array */
const struct gdb_mem_region gdb_mem_region_array[0];

/* Number of memory regions */
const size_t gdb_mem_num_regions;

/**
* Given a starting address and length of a memory block, find a memory
* region descriptor from the memory region array where the memory block
* fits inside the memory region.
*
* @param addr Starting address of the memory block
* @param len  Length of the memory block
*
* @return Pointer to the memory region description if found.
*         NULL if not found.
*/
#if defined(__GNUC__)
#pragma GCC diagnostic push
/* Required due to gdb_mem_region_array having a default size of zero. */
#pragma GCC diagnostic ignored "-Warray-bounds"
#endif

static inline const
   struct gdb_mem_region *find_memory_region(const uintptr_t addr, const size_t len)
{
 const struct gdb_mem_region *r, *ret = NULL;
 unsigned int idx;

 for (idx = 0; idx < gdb_mem_num_regions; idx++) {
   r = &gdb_mem_region_array[idx];

   if ((addr >= r->start) &&
       (addr < r->end) &&
       ((addr + len) >= r->start) &&
       ((addr + len) < r->end)) {
     ret = r;
     break;
   }
 }

 return ret;
}

#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

bool gdb_mem_can_read(const uintptr_t addr, const size_t len, uint8_t *align)
{
 bool ret = false;
 const struct gdb_mem_region *r;

 if (gdb_mem_num_regions == 0) {
   /*
                * No region is defined.
                * Assume memory access is not restricted, and there is
                * no alignment requirement.
    */
   *align = 1;
   ret = true;
 } else {
   r = find_memory_region(addr, len);
   if (r != NULL) {
     if ((r->attributes & GDB_MEM_REGION_READ) ==
         GDB_MEM_REGION_READ) {
       if (r->alignment > 0) {
         *align = r->alignment;
       } else {
         *align = 1;
       }
       ret = true;
     }
   }
 }

 return ret;
}

bool gdb_mem_can_write(const uintptr_t addr, const size_t len, uint8_t *align)
{
 bool ret = false;
 const struct gdb_mem_region *r;

 if (gdb_mem_num_regions == 0) {
   /*
                * No region is defined.
                * Assume memory access is not restricted, and there is
                * no alignment requirement.
    */
   *align = 1;
   ret = true;
 } else {
   r = find_memory_region(addr, len);
   if (r != NULL) {
     if ((r->attributes & GDB_MEM_REGION_WRITE) ==
         GDB_MEM_REGION_WRITE) {
       if (r->alignment > 0) {
         *align = r->alignment;
       } else {
         *align = 1;
       }

       ret = true;
     }
   }
 }

 return ret;
}

size_t gdb_bin2hex(const uint8_t *buf, size_t buflen, char *hex, size_t hexlen)
{
 if ((hexlen + 1) < buflen * 2) {
   return 0;
 }

 for (size_t i = 0; i < buflen; i++) {
   if (hex2char(buf[i] >> 4, &hex[2 * i]) < 0) {
     return 0;
   }
   if (hex2char(buf[i] & 0xf, &hex[2 * i + 1]) < 0) {
     return 0;
   }
 }

 return 2 * buflen;
}


/**
* Add preamble and termination to the given data.
*
* It returns 0 if the packet was acknowledge, -1 otherwise.
*/
static int gdb_send_packet(const uint8_t *data, size_t len)
{
 uint8_t buf[2];
 uint8_t checksum = 0;

 /* Send packet start */
 z_gdb_putchar('$');

 /* Send packet data and calculate checksum */
 while (len-- > 0) {
   checksum += *data;
   z_gdb_putchar(*data++);
 }

 /* Send the checksum */
 z_gdb_putchar('#');

 if (gdb_bin2hex(&checksum, 1, buf, sizeof(buf)) == 0) {
   return -1;
 }

 z_gdb_putchar(buf[0]);
 z_gdb_putchar(buf[1]);

 if (z_gdb_getchar() == '+') {
   return 0;
 }

 /* Just got an invalid response */
 return -1;
}

/**
* Receives one whole GDB packet.
*
* @retval  0 Success
* @retval -1 Checksum error
* @retval -2 Incoming packet too large
*/
static int gdb_get_packet(uint8_t *buf, size_t buf_len, size_t *len)
{
 uint8_t ch = '0';
 uint8_t expected_checksum, checksum = 0;
 uint8_t checksum_buf[2];

 /* Wait for packet start */
 checksum = 0;

 /* wait for the start character, ignore the rest */
 while (ch != '$') {
   ch = z_gdb_getchar();
 }

 *len = 0;
 /* Read until receive '#' */
 while (true) {
   ch = z_gdb_getchar();

   if (ch == '#') {
     break;
   }

   /* Only put into buffer if not full */
   if (*len < (buf_len - 1)) {
     buf[*len] = ch;
   }

   checksum += ch;
   (*len)++;
 }

 buf[*len] = '\0';

 /* Get checksum now */
 checksum_buf[0] = z_gdb_getchar();
 checksum_buf[1] = z_gdb_getchar();

 if (hex2bin(checksum_buf, 2, &expected_checksum, 1) == 0) {
   return -1;
 }

 /* Verify checksum */
 if (checksum != expected_checksum) {
   fprintf("Gdbstub: Bad checksum. Got 0x%x but was expecting: 0x%x\n",
           (uint16_t*)checksum, expected_checksum);
   /* NACK packet */
   z_gdb_putchar('-');
   return -1;
 }

 /* ACK packet */
 z_gdb_putchar('+');

 if (*len >= (buf_len - 1)) {
   return -2;
 } else {
   return 0;
 }
}

/**
* Send a exception packet "T <value>"
*/
static int gdb_send_exception(uint8_t *buf, size_t len, uint8_t exception)
{
 size_t size;

#ifdef CONFIG_GDBSTUB_TRACE
 printk("gdbstub:%s exception=0x%x\n", __func__, exception);
#endif

 *buf = 'T';
 size = gdb_bin2hex(&exception, 1, buf + 1, len - 1);
 if (size == 0) {
   return -1;
 }

 /* Related to 'T' */
 size++;

 return gdb_send_packet(buf, size);
}

static bool gdb_qsupported(uint8_t *buf, size_t len, enum gdb_loop_state *next_state)
{
 size_t n = 0;
 const char *c_buf = (const char *) buf;

 if (strstr(buf, "qSupported") != c_buf) {
   return false;
 }

 gdb_send_packet(buf, n);
 return true;
}

static void gdb_q_packet(uint8_t *buf, size_t len, enum gdb_loop_state *next_state)
{
 if (gdb_qsupported(buf, len, next_state)) {
   return;
 }

 gdb_send_packet(NULL, 0);
}

static void gdb_v_packet(uint8_t *buf, size_t len, enum gdb_loop_state *next_state)
{
 gdb_send_packet(NULL, 0);
}

/**
 * Synchronously communicate with gdb on the host
 */
int z_gdb_main_loop(struct gdb_ctx *ctx)
{
 /* 'static' modifier is intentional so the buffer
        * is not declared inside running stack, which may
        * not have enough space.
  */
 static uint8_t buf[GDB_PACKET_SIZE];
 enum gdb_loop_state state;

 state = GDB_LOOP_RECEIVING;

 /* Only send exception if this is not the first
        * GDB break.
  */
 if (not_first_start) {
   gdb_send_exception(buf, sizeof(buf), ctx->exception);
 } else {
   not_first_start = true;
 }

#define CHECK_ERROR(condition)			\
       {					\
               if ((condition)) {		\
                       state = GDB_LOOP_ERROR;	\
                       break;			\
               }				\
       }

#define CHECK_SYMBOL(c)					\
       {							\
               CHECK_ERROR(ptr == NULL || *ptr != (c));	\
               ptr++;						\
       }

#define CHECK_UINT(arg)							\
       {								\
               arg = strtoul((const char *)ptr, (char **)&ptr, 16);	\
               CHECK_ERROR(ptr == NULL);				\
       }

 while (state == GDB_LOOP_RECEIVING) {
   uint8_t *ptr;
   size_t data_len, pkt_len;
   uintptr_t addr;
   uint32_t type;
   int ret;

   ret = gdb_get_packet(buf, sizeof(buf), &pkt_len);
   if ((ret == -1) || (ret == -2)) {
     /*
                        * Send error and wait for next packet.
                        *
                        * -1: Checksum error.
                        * -2: Packet too big.
      */
     gdb_send_packet(GDB_ERROR_GENERAL, 3);
     continue;
   }

   if (pkt_len == 0) {
     continue;
   }

   ptr = buf;

#ifdef CONFIG_GDBSTUB_TRACE
   printk("gdbstub:%s got '%c'(0x%x) command\n", __func__, *ptr, *ptr);
#endif

   switch (*ptr++) {

   /**
                * Read from the memory
                * Format: m addr,length
    */
   case 'm':
     CHECK_UINT(addr);
     CHECK_SYMBOL(',');
     CHECK_UINT(data_len);

     /* Read Memory */

     /*
                        * GDB ask the guest to read parameters when
                        * the user request backtrace. If the
                        * parameter is a NULL pointer this will cause
                        * a fault. Just send a packet informing that
                        * this address is invalid
      */
     if (addr == 0L) {
       gdb_send_packet(GDB_ERROR_MEMORY, 3);
       break;
     }
     ret = arch_gdb_mem_read(buf, sizeof(buf), addr, data_len);
     CHECK_ERROR(ret == -1);
     gdb_send_packet(buf, ret);
     break;

   /**
                * Write to memory
                * Format: M addr,length:val
    */
   case 'M':
     CHECK_UINT(addr);
     CHECK_SYMBOL(',');
     CHECK_UINT(data_len);
     CHECK_SYMBOL(':');

     if (addr == 0L) {
       gdb_send_packet(GDB_ERROR_MEMORY, 3);
       break;
     }

     /* Write Memory */
     pkt_len = arch_gdb_mem_write(ptr, addr, data_len);
     CHECK_ERROR(pkt_len == -1);
     gdb_send_packet("OK", 2);
     break;

   /*
                * Continue ignoring the optional address
                * Format: c addr
    */
   case 'c':
     arch_gdb_continue();
     state = GDB_LOOP_CONTINUE;
     break;

   /*
                * Step one instruction ignoring the optional address
                * s addr..addr
    */
   case 's':
     arch_gdb_step();
     state = GDB_LOOP_CONTINUE;
     break;

   /*
                * Read all registers
                * Format: g
    */
   case 'g':
     pkt_len = arch_gdb_reg_readall(ctx, buf, sizeof(buf));
     CHECK_ERROR(pkt_len == 0);
     gdb_send_packet(buf, pkt_len);
     break;

   /**
                * Write the value of the CPU registers
                * Format: G XX...
    */
   case 'G':
     pkt_len = arch_gdb_reg_writeall(ctx, ptr, pkt_len - 1);
     CHECK_ERROR(pkt_len == 0);
     gdb_send_packet("OK", 2);
     break;

   /**
                * Read the value of a register
                * Format: p n
    */
   case 'p':
     CHECK_UINT(addr);

     /* Read Register */
     pkt_len = arch_gdb_reg_readone(ctx, buf, sizeof(buf), addr);
     CHECK_ERROR(pkt_len == 0);
     gdb_send_packet(buf, pkt_len);
     break;

   /**
                * Write data into a specific register
                * Format: P register=value
    */
   case 'P':
     CHECK_UINT(addr);
     CHECK_SYMBOL('=');

     pkt_len = arch_gdb_reg_writeone(ctx, ptr, strlen(ptr), addr);
     CHECK_ERROR(pkt_len == 0);
     gdb_send_packet("OK", 2);
     break;

   /*
                * Breakpoints and Watchpoints
    */
   case 'z':
   case 'Z':
     CHECK_UINT(type);
     CHECK_SYMBOL(',');
     CHECK_UINT(addr);
     CHECK_SYMBOL(',');
     CHECK_UINT(data_len);

     if (buf[0] == 'Z') {
       ret = arch_gdb_add_breakpoint(ctx, type,
                                     addr, data_len);
     } else if (buf[0] == 'z') {
       ret = arch_gdb_remove_breakpoint(ctx, type,
                                        addr, data_len);
     }

     if (ret == -2) {
       /* breakpoint/watchpoint not supported */
       gdb_send_packet(NULL, 0);
     } else if (ret == -1) {
       state = GDB_LOOP_ERROR;
     } else {
       gdb_send_packet("OK", 2);
     }

     break;


   case 'k':
     ConfigureParams.Log.bConfirmQuit = false;
     ConfigureParams.Memory.bAutoSave = false;
     Main_RequestQuit(0);
     return 0;
   /* What cause the pause  */
   case '?':
     gdb_send_exception(buf, sizeof(buf),
                        ctx->exception);
     break;

   /* Query packets*/
   case 'q':
   case 'Q':
     gdb_q_packet(buf, sizeof(buf), &state);
     break;

   /* v packets */
   case 'v':
     gdb_v_packet(buf, sizeof(buf), &state);
     break;

   /*
                * Not supported action
    */
   default:
     gdb_send_packet(NULL, 0);
     break;
   }

   /*
                * If this is an recoverable error, send an error message to
                * GDB and continue the debugging session.
    */
   if (state == GDB_LOOP_ERROR) {
     gdb_send_packet(GDB_ERROR_GENERAL, 3);
     state = GDB_LOOP_RECEIVING;
   }
 }

#undef CHECK_ERROR
#undef CHECK_UINT
#undef CHECK_SYMBOL

 return 0;
}

int gdb_init(void)
{
 if (z_gdb_backend_init() == -1) {
   fprintf(stderr, "Could not initialize gdbstub backend.\n");
   return -1;
 }

 arch_gdb_init();

 z_gdb_entry();

 return 0;
}

void gdb_destroy(void)
{
  z_gdb_backend_destroy();
}
