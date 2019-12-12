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

var fuzzer = require("./fuzzer.js");
var config = require("./config.js");
var mutator = require("./mutator.js");

exports.fuzzer = fuzzer;
exports.config = config;
exports.mutator = mutator;

exports.target_module = null;
exports.fuzzer_test_one_input = null;
exports.use_java = false;
exports.init_function = function () {};

// Stalker tuning
var STALKER_QUEUE_CAP = 100000000;
var STALKER_QUEUE_DRAIN_INT = 1000*1000;

Stalker.trustThreshold = 0;
Stalker.queueCapacity = STALKER_QUEUE_CAP;
Stalker.queueDrainInterval = STALKER_QUEUE_DRAIN_INT;


rpc.exports.loop = function () {

  function body () {
  
    exports.init_function();

    if (exports.fuzzer_test_one_input === null) {
      throw "ERROR: fuzzer_test_one_input not set! Cannot start the fuzzing loop!";
    }

    var maps = function() {

        var maps = Process.enumerateModulesSync();
        var i = 0;
        
        maps.map(function(o) { o.id = i++; });
        maps.map(function(o) { o.end = o.base.add(o.size); });

        return maps;

    }();

    var start_addr = ptr(0);
    var end_addr = ptr("-1");

    // TO USER: Tweak this as your needs
    if (exports.target_module !== null) {
      maps.forEach(function(m) {

        if (m.name == exports.target_module) {
          start_addr = m.base;
          end_addr = m.end;
        } else {
          Stalker.exclude(m);
        }

      });
    }
    
    var prev_loc_ptr = Memory.alloc(32);
    var prev_loc = 0;

    function afl_maybe_log (context) {
      
      var cur_loc = context.pc.toInt32();
      
      /*var n = "";
      maps.forEach(function(m) {
        if (context.pc >= m.base && context.pc < m.end) {
          n = m.name;
        }
      });
      console.log("exec " + n + "  " + context.pc);*/
      
      cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
      cur_loc &= config.MAP_SIZE - 1;

      //fuzzer.trace_bits[cur_loc ^ prev_loc]++;
      var x = fuzzer.trace_bits.add(cur_loc ^ prev_loc);
      x.writeU8((x.readU8() +1) & 0xff);

      prev_loc = cur_loc >> 1;

    }

    var generic_transform = function (iterator) {

      var i = iterator.next();
      
      var cur_loc = i.address;

      /*var n = "";
      maps.forEach(function(m) {
        if (cur_loc >= m.base && cur_loc < m.end) {
          n = m.name;
        }
      });
      console.log("transform " + n + "  " + cur_loc);*/

      if (cur_loc.compare(start_addr) > 0 &&
          cur_loc.compare(end_addr) < 0)
        iterator.putCallout(afl_maybe_log);

      do iterator.keep()
      while ((i = iterator.next()) !== null);

    }

    var transforms = {
      "x64": function (iterator) {
      
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

    Stalker.follow(Process.getCurrentThreadId(), {
        events: {
            call: false,
            ret: false,
            exec: false,
            block: false,
            compile: true
        },
        
      transform: transforms[Process.arch],
      //transform: generic_transform,
    });

    var payload_memory = Memory.alloc(config.MAX_FILE);
    var payload_len = 0;

    function runner(arr_buf) {
      
      var b = new Uint8Array(arr_buf);
      var s = Math.min(b.length, config.MAX_FILE);
      Memory.writeByteArray(payload_memory, b, s);

      //Stalker.flush();
      exports.fuzzer_test_one_input(payload_memory, s);
      //Stalker.flush();

    }
    
    Process.setExceptionHandler(function (details) {
      send({
        "event": "crash",
        "err": details,
        "stage": fuzzer.stage_name
      }, payload_memory.readByteArray(payload_len));
      return false;
    });

    function hex_to_arrbuf(hexstr) {

      var buf = [];
      for(var i = 0; i < hexstr.length; i+=2)
          buf.push(parseInt(hexstr.substring(i, i + 2), 16));

      buf = new Uint8Array(buf);
      return buf.buffer;

    }

    console.log(" >> Starting fuzzing loop...");
    
    while (true) {

      send({
        "event": "next",
        "stage": fuzzer.stage_name,
        "total_execs": fuzzer.total_execs,
      });

      var buf = undefined;
      var op = recv("input", function (val) {
        buf = hex_to_arrbuf(val.buf);
        //val.was_fuzzed
      });

      op.wait();

      try {
        /* RANDOM HAVOC */
        fuzzer.fuzz_havoc(buf, runner, false);
      } catch(err) {
        return;
      }

    }

  }
  
  if (exports.use_java) {
    if (!Java.available)
      throw "ERROR: Java is not available in the target!";
    Java.perform(body);
  }
  else body();

}

