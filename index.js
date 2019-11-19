/*

   american fuzzy lop++ - frida agent instrumentation
   --------------------------------------------------

   Written and maintained by Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2019 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

var fuzz = require("./fuzz.js");
var config = require("./config.js");

/************************** USER CONFIGURABLE BITS ***************************/

//var TARGET_MODULE = "test_linux64";
var TARGET_MODULE = "libnative-lib.so";
Module.ensureInitialized(TARGET_MODULE);

//var TARGET_FUNCTION = DebugSymbol.fromName("target_func").address;
var TARGET_FUNCTION = Module.findExportByName(TARGET_MODULE, "target_func");
var RET_TYPE = "void";
var ARGS_TYPES = ['pointer', 'int'];

var payload_memory = Memory.alloc(config.MAX_FILE);
// var zeroed_bytes = new Uint8Array(config.MAX_FILE);

function fuzzer_test_one_input (arr_buf) {

  var b = new Uint8Array(arr_buf);
  
  // Memory.writeByteArray(payload_memory, zeroed_bytes);
  Memory.writeByteArray(payload_memory, b);
  
  func_handle (payload_memory, b.length);

}

/*****************************************************************************/

var STALKER_QUEUE_CAP = 100000000;
var STALKER_QUEUE_DRAIN_INT = 1000*1000;

var func_handle = new NativeFunction(TARGET_FUNCTION, RET_TYPE, ARGS_TYPES);

// Stalker tuning
Stalker.trustThreshold = 0;
Stalker.queueCapacity = STALKER_QUEUE_CAP;
Stalker.queueDrainInterval = STALKER_QUEUE_DRAIN_INT;

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
maps.forEach(function(m) {

  if (m.name == TARGET_MODULE) {
    start_addr = m.base;
    end_addr = m.end;
  }

});

/*
Process.setExceptionHandler(function (details) {

  send({"event": "crash", "details": details});
  return false; // Let the app crash

});*/

var prev_loc_ptr = Memory.alloc(32);
var prev_loc = 0;

function afl_maybe_log (context) {
  
  var cur_loc = context.pc.toInt32();
  
  cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= config.MAP_SIZE - 1;

  //fuzz.trace_bits[cur_loc ^ prev_loc]++;
  var x = fuzz.trace_bits.add(cur_loc ^ prev_loc);
  x.writeU8((x.readU8() +1) & 0xff);

  prev_loc = cur_loc >> 1;

}

var generic_transform = function (iterator) {

  var i = iterator.next();
  
  var cur_loc = i.address;
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
      // rbx = fuzz.trace_bits
      iterator.putMovRegAddress("rbx", fuzz.trace_bits);
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

var gc_cnt = 0;
Interceptor.attach(TARGET_FUNCTION, {
    // This is a performance problem, wait for https://github.com/frida/frida/issues/1036
    onEnter: function (args) {
        Stalker.follow(Process.getCurrentThreadId(), {
          events: {
              call: false,
              ret: false,
              exec: false,
              block: false,
              compile: true
          },
          
        transform: transforms[Process.arch],
      });

    },

    onLeave: function (retval) {
        Stalker.unfollow(Process.getCurrentThreadId())
        Stalker.flush()
        if(gc_cnt % 100 == 0)
            Stalker.garbageCollect();
        gc_cnt++;

    }

});

function hex_to_arrbuf(hexstr) {

  var buf = [];
  for(var i = 0; i < hexstr.length; i+=2)
      buf.push(parseInt(hexstr.substring(i, i + 2), 16));

  buf = new Uint8Array(buf);
  return buf.buffer;

}

fuzzer_test_one_input (new ArrayBuffer(8));

rpc.exports.loop = function () {

  console.log(" >> Starting fuzzing loop...")
  
  while (true) {

    send({
      "event": "next",
      "stage": fuzz.stage_name,
      "total_execs": fuzz.total_execs,
    });

    var buf = undefined;
    var op = recv("input", function (val) {
      buf = hex_to_arrbuf(val.buf);
      //val.was_fuzzed
    });

    op.wait();

    /* RANDOM HAVOC */
    fuzz.fuzz_havoc(buf, fuzzer_test_one_input, false);

  }

}






