/*

   frida-fuzzer - frida agent instrumentation
   ------------------------------------------

   Written and maintained by Andrea Fioraldi <andreafioraldi@gmail.com>
   Based on American Fuzzy Lop by Michal Zalewski

   Copyright 2019 Andrea Fioraldi. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

var config  = require("./config.js");
var queue = require("./queue.js");

exports.trace_bits  = Memory.alloc(config.MAP_SIZE);
exports.virgin_bits = Memory.alloc(config.MAP_SIZE);
for (var i = 0; i < config.MAP_SIZE; i += 4)
  exports.virgin_bits.add(i).writeU32(0xffffffff);

exports.top_rated = Memory.alloc(config.MAP_SIZE * Process.pointerSize);
exports.score_changed = false;

exports.map_rate = 0;

/* Init count class lookup */

var count_class_lookup8 = new Uint8Array(256);
count_class_lookup8[0] = 0;
count_class_lookup8[1] = 1;
count_class_lookup8[2] = 2;
count_class_lookup8[4] = 3;
for (var i = 4; i <= 7; ++i)
  count_class_lookup8[i] = 8;
for (var i = 8; i <= 15; ++i)
  count_class_lookup8[i] = 16;
for (var i = 16; i <= 31; ++i)
  count_class_lookup8[i] = 32;
for (var i = 32; i <= 127; ++i)
  count_class_lookup8[i] = 64;
for (var i = 128; i <= 255; ++i)
  count_class_lookup8[i] = 128;

var count_class_lookup16_ptr = Memory.alloc(65536 * 2);

for (var b1 = 0; b1 < 256; b1++) {
  for (var b2 = 0; b2 < 256; b2++) {
    count_class_lookup16_ptr.add(((b1 << 8) + b2) * 2).writeU16(
      (count_class_lookup8[b1] << 8) | count_class_lookup8[b2]
    );
  }
}

exports.count_class_lookup16 = count_class_lookup16_ptr;

exports.__cm = new CModule(`

#include <stdint.h>
#include <stdio.h>
#include <glib.h>

#define MAP_SIZE __MAP_SIZE__

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef int32_t s32;

struct __attribute__((packed)) QEntry {

  u8* buf;
  u8* trace_mini;
  u32 size;
  u32 exec_ms;
  u32 tc_ref;
  u8 favored;
  u8 was_fuzzed;

};

void classify_counts(u32* mem, u16* count_class_lookup16) {

  u32 i = MAP_SIZE >> 2;
  
  while (i--) {
  
    /* Optimize for sparse bitmaps. */

    if (*mem) {
      
      u16* mem16 = (u16*)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];

    }

    ++mem;

  }

}

int has_new_bits(u8* trace_bits, u8* virgin_map) {

  u32* current = (u32*)trace_bits;
  u32* virgin = (u32*)virgin_map;

  u32 i = MAP_SIZE >> 2;

  int ret = 0;

  while (i--) {

    if (*current && (*current & *virgin)) {

      if (ret < 2) {

        u8* cur = (u8*)current;
        u8* vir = (u8*)virgin;

        /* Looks like we have not found any new bytes yet; see if any non-zero
           bytes in current[] are pristine in virgin[]. */

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff))
          ret = 2;
        else
          ret = 1;

      }

      *virgin &= ~*current;

    }

    ++current;
    ++virgin;

  }

  return ret;

}

static void minimize_bits(u8* dst, u8* src) {

  u32 i = 0;

  while (i < MAP_SIZE) {

    if (*(src++)) dst[i >> 3] |= 1 << (i & 7);
    i++;

  }

}

s32 update_bitmap_score_body(struct QEntry* q, struct QEntry** top_rated, u8* trace_bits, u8* virgin_bits) {

  u32 fav_factor = q->exec_ms * q->size;
  s32 cnt = 0;
  u8 score_changed = 0;
  u32 i;

  for (i = 0; i < MAP_SIZE; ++i) {
  
    if (trace_bits[i]) {

      if (top_rated[i]) {

        /* Faster-executing or smaller test cases are favored. */
  
        if (fav_factor > top_rated[i]->exec_ms * top_rated[i]->size)
          continue;
  
        if (!--top_rated[i]->tc_ref) {
          g_free(top_rated[i]->trace_mini);
          top_rated[i]->trace_mini = NULL;
        }
  
      }
  
      /* Insert ourselves as the new winner. */
  
      top_rated[i] = q;
      q->tc_ref++;
      
      if (q->trace_mini == NULL) {
  
        q->trace_mini = g_malloc0(MAP_SIZE >> 3);
        minimize_bits(q->trace_mini, trace_bits);
  
      }
  
      score_changed = 1;

    }
    
    if (virgin_bits[i] != 0xff)
      ++cnt;
  
  }
  
  if (score_changed) // dirty hack to return 2 values
    return -cnt;
  return cnt;

}

  `.replace("__MAP_SIZE__", ""+config.MAP_SIZE)
);

exports.classify_counts = new NativeFunction(
  exports.__cm.classify_counts,
  "void",
  ["pointer", "pointer"]
);

exports.has_new_bits = new NativeFunction(
  exports.__cm.has_new_bits,
  "int",
  ["pointer", "pointer"]
);

var update_bitmap_score_body = new NativeFunction(
  exports.__cm.update_bitmap_score_body,
  "int",
  ["pointer", "pointer", "pointer", "pointer"]
);

exports.update_bitmap_score = function (q) {

  if (config.SKIP_SCORE_FAV) return;

  var cnt = update_bitmap_score_body(q.ptr, exports.top_rated, exports.trace_bits, exports.virgin_bits);
  if (cnt < 0) {
    exports.score_changed = true;
    cnt = -cnt;
  }

  exports.map_rate = cnt * 100 / config.MAP_SIZE;

}

exports.save_if_interesting = function (buf, exec_ms) {
  
  var hnb = exports.has_new_bits(exports.trace_bits, exports.virgin_bits);
  if (hnb == 0)
    return true;
  
  queue.add(buf, exec_ms, (hnb == 2));
  exports.update_bitmap_score(queue.last());

  return false;  
  
}
