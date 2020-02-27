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

var config = require("./config.js");
var bitmap = require("./bitmap.js");

// trustThreshold must be 0, don't change it and especially don't set it to -1
Stalker.trustThreshold = 0;

exports.prev_loc_map = {}

exports.start_tracing = function(thread_id, target_module) {
    
  var start_addr = ptr(0);
  var end_addr = ptr("-1");

  var maps = function() {

      var maps = Process.enumerateModulesSync();
      var i = 0;
      
      maps.map(function(o) { o.id = i++; });
      maps.map(function(o) { o.end = o.base.add(o.size); });

      return maps;

  }();

  if (target_module !== null) {
    maps.forEach(function(m) {

      if (m.name == target_module || m == target_module) {
        start_addr = m.base;
        end_addr = m.end;
      } else {
        Stalker.exclude(m);
      }

    });
  } else {
    maps.forEach(function(m) {

      if (m.name.startsWith("libc.") || m.name.startsWith("libSystem.") || m.name.startsWith("frida")) {
        Stalker.exclude(m);
      }

    });
  }

  var prev_loc_ptr = exports.prev_loc_map[thread_id];
  if (prev_loc_ptr === undefined) {
    prev_loc_ptr = Memory.alloc(32);
    exports.prev_loc_map[thread_id] = prev_loc_ptr;
  }

  var transform = undefined;
  if (Process.arch == "ia32") {

    // Fast inline instrumentation for x86
    exports.transform_ia32 = function (iterator) {
      
      var i = iterator.next();
      
      var cur_loc = i.address;
      
      if (cur_loc.compare(start_addr) > 0 &&
          cur_loc.compare(end_addr) < 0) {
      
        cur_loc = cur_loc.shr(4).xor(cur_loc.shl(8));
        cur_loc = cur_loc.and(config.MAP_SIZE - 1);
        
        iterator.putPushfx();
        iterator.putPushReg("edx");
        iterator.putPushReg("ecx");
        iterator.putPushReg("ebx");

        // edx = cur_loc
        iterator.putMovRegAddress("edx", cur_loc);
        // ebx = &prev_loc
        iterator.putMovRegAddress("ebx", prev_loc_ptr);
        // ecx = *ebx
        iterator.putMovRegRegPtr("ecx", "ebx");
        // ecx ^= edx
        iterator.putXorRegReg("ecx", "edx");
        // edx = cur_loc >> 1
        iterator.putMovRegAddress("edx", cur_loc.shr(1));
        // *ebx = edx
        iterator.putMovRegPtrReg("ebx", "edx");
        // ebx = bitmap.trace_bits
        iterator.putMovRegAddress("ebx", bitmap.trace_bits);
        // ebx += ecx
        iterator.putAddRegReg("ebx", "ecx");
        // (*ebx)++
        iterator.putU8(0xfe); // inc byte ptr [ebx]
        iterator.putU8(0x03);
    
        iterator.putPopReg("ebx");
        iterator.putPopReg("ecx");
        iterator.putPopReg("edx");
        iterator.putPopfx();
      
      }
      
      do iterator.keep()
      while ((i = iterator.next()) !== null);

    };

    transform = exports.transform_ia32;

  } else if (Process.arch == "x64") {

    // Fast inline instrumentation for x86_64
    exports.transform_x64 = function (iterator) {
      
      var i = iterator.next();
      
      var cur_loc = i.address;
      
      if (cur_loc.compare(start_addr) > 0 &&
          cur_loc.compare(end_addr) < 0) {
      
        cur_loc = cur_loc.shr(4).xor(cur_loc.shl(8));
        cur_loc = cur_loc.and(config.MAP_SIZE - 1);
        
        iterator.putPushfx();
        iterator.putPushReg("rdx");
        iterator.putPushReg("rcx");
        iterator.putPushReg("rbx");

        // rdx = cur_loc
        iterator.putMovRegAddress("rdx", cur_loc);
        // rbx = &prev_loc
        iterator.putMovRegAddress("rbx", prev_loc_ptr);
        // rcx = *rbx
        iterator.putMovRegRegPtr("rcx", "rbx");
        // rcx ^= rdx
        iterator.putXorRegReg("rcx", "rdx");
        // rdx = cur_loc >> 1
        iterator.putMovRegAddress("rdx", cur_loc.shr(1));
        // *rbx = rdx
        iterator.putMovRegPtrReg("rbx", "rdx");
        // rbx = bitmap.trace_bits
        iterator.putMovRegAddress("rbx", bitmap.trace_bits);
        // rbx += rcx
        iterator.putAddRegReg("rbx", "rcx");
        // (*rbx)++
        iterator.putU8(0xfe); // inc byte ptr [rbx]
        iterator.putU8(0x03);
    
        iterator.putPopReg("rbx");
        iterator.putPopReg("rcx");
        iterator.putPopReg("rdx");
        iterator.putPopfx();
      
      }
      
      do iterator.keep()
      while ((i = iterator.next()) !== null);

    };

    transform = exports.transform_x64;
  
  } else {
  
    exports.__cm = new CModule(`

    #include <stdint.h>
    #include <gum/gumstalker.h>
  
    typedef uint8_t u8;
    typedef uint16_t u16;
    typedef uint32_t u32;
  
    static void afl_maybe_log (GumCpuContext * cpu_context, gpointer user_data) {
  
      u8 * trace_bits = (u8*)(__TRACE_BITS__);
      uintptr_t * prev_loc_ptr = (uintptr_t*)(__PREV_LOC__);
      
      uintptr_t cur_loc = (uintptr_t)user_data;
      
      trace_bits[cur_loc ^ (*prev_loc_ptr)]++;
      *prev_loc_ptr = cur_loc >> 1;
  
    }
  
    void transform (GumStalkerIterator * iterator, GumStalkerWriter * output, gpointer user_data) {
  
      cs_insn * i;
      gum_stalker_iterator_next (iterator, &i);
      
      uintptr_t cur_loc = i->address;
      
      if (cur_loc >= (__START__) && cur_loc < (__END__)) {
      
        cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
        cur_loc &= (__MAP_SIZE__) - 1;
      
        gum_stalker_iterator_put_callout (iterator, afl_maybe_log, (gpointer)cur_loc, NULL);
      
      }
  
      do gum_stalker_iterator_keep (iterator);
      while (gum_stalker_iterator_next (iterator, &i));
  
    }
  
    `.replace("__TRACE_BITS__", bitmap.trace_bits.toString())
     .replace("__PREV_LOC__", prev_loc_ptr.toString())
     .replace("__START__", start_addr.toString())
     .replace("__END__", end_addr.toString())
     .replace("__MAP_SIZE__", config.MAP_SIZE.toString())
    );

    transform = exports.__cm.transform;

  }
  
  Stalker.follow(thread_id, {
      events: {
          call: false,
          ret: false,
          exec: false,
          block: false,
          compile: true
      },
      
    transform: transform
  });

}
