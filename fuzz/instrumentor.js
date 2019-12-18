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
var fuzzer = require("./fuzzer.js");

// Stalker tuning (from frizzer, thanks to the authos)
// Ole approves, I don't really know what this the improvement
var STALKER_QUEUE_CAP = 100000000;
var STALKER_QUEUE_DRAIN_INT = 1000*1000;

// trustThreshold must be 0, don't change it and especially don't set it to -1
Stalker.trustThreshold = 0;
Stalker.queueCapacity = STALKER_QUEUE_CAP;
Stalker.queueDrainInterval = STALKER_QUEUE_DRAIN_INT;

var start_addr = ptr(0);
var end_addr = ptr("-1");

var prev_loc_ptr = Memory.alloc(32);
var prev_loc = 0;

function afl_maybe_log (context) { // TODO CModule
  
  var cur_loc = context.pc.toInt32();
  
  cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= config.MAP_SIZE - 1;

  //fuzzer.trace_bits[cur_loc ^ prev_loc]++;
  var x = fuzzer.trace_bits.add(cur_loc ^ prev_loc);
  x.writeU8((x.readU8() +1) & 0xff);

  prev_loc = cur_loc >> 1;

}

var generic_transform = function (iterator) { // TODO CModule

  var i = iterator.next();
  
  var cur_loc = i.address;

  if (cur_loc.compare(start_addr) > 0 &&
      cur_loc.compare(end_addr) < 0)
    iterator.putCallout(afl_maybe_log);

  do iterator.keep()
  while ((i = iterator.next()) !== null);

}

exports.transforms = {
  "x64": function (iterator) { // TODO CModule
  
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
      // rbx = fuzzer.trace_bits
      iterator.putMovRegAddress("rbx", fuzzer.trace_bits);
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

  },
  // TODO inline ARM code
  "ia32": generic_transform,
  "arm": generic_transform,
  "arm64": generic_transform
};

exports.start_tracing = function(thread_id, target_module) {

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
  }
  
  Stalker.follow(thread_id, {
      events: {
          call: false,
          ret: false,
          exec: false,
          block: false,
          compile: true
      },
      
    transform: exports.transforms[Process.arch],
    //transform: generic_transform,
  });

}
