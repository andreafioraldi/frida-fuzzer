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

var config  = require("./config.js");
var mutator = require("./mutator.js");

exports.stage_name = "init";
exports.stage_cur  = 0;
exports.stage_max  = 0;

exports.total_execs = 0;
exports.exec_speed = 0;

exports.trace_bits  = Memory.alloc(config.MAP_SIZE);
exports.virgin_bits = new Uint8Array(config.MAP_SIZE);
for (var i = 0; i <= config.MAP_SIZE; ++i)
  exports.virgin_bits[i] = 0xff;

var zeroed_bits = new Uint8Array(config.MAP_SIZE); // TODO memset(..., 0, ...)

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


function has_new_bits() {

  var r = 0;
  var vir = exports.virgin_bits;
  
  for (var i = 0; i < config.MAP_SIZE; ++i) {
  
    var cur = exports.trace_bits.add(i);
    var val = cur.readU8();
  
    if (val != 0 && (val & vir[i]) != 0) {
    
      if (r < 2) {
      
        if (vir[i] == 0xff) r = 2;
        else r = 1;
      
      }
      
      vir[i] &= ~val;
    
    }
  
  }
  
  return r;

}

function save_if_interesting (buf, exec_us) {
  
  var hnb = has_new_bits();
  if (hnb == 0)
    return;
  
  console.log("saving")
  send({
    "event": "interesting",
    "exec_us": exec_us,
    "new_cov": (hnb == 2),
    "stage": exports.stage_name,
    "total_execs": exports.total_execs,
    "exec_speed": exports.exec_speed
  }, buf);
  
}


function common_fuzz_stuff(buf, callback) {

  Memory.writeByteArray(exports.trace_bits, zeroed_bits);

  var ts = (new Date()).getTime();
  callback(buf);
  var exec_us = (new Date()).getTime() - ts;
  
  // Classify counts
  for (var i = 0; i < config.MAP_SIZE; ++i) {

    var ptr = exports.trace_bits.add(i);
    ptr.writeU8(count_class_lookup8[ptr.readU8()]);

  }
  
  exports.exec_speed = exec_us;
  ++exports.execs_num;
  
  save_if_interesting(buf, exec_us);

}

exports.fuzz_havoc = function (buf, callback, is_splice) {

  if (!is_splice)  {
    exports.stage_name = "havoc";
    exports.stage_max = config.HAVOC_CYCLES; // TODO perf_score & co
  } else {
    exports.stage_name = "splice";
    exports.stage_max = config.SPLICE_CYCLES; // TODO perf_score & co
  }

  for (exports.stage_cur = 0; exports.stage_cur < exports.stage_max;
       exports.stage_cur++) {

    var muted = buf.slice(0);
    muted = mutator.mutate_havoc(muted);
    
    common_fuzz_stuff(muted, callback);
 
  }

}

