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
var instr = require("./instrumentor.js");
var utils = require("./utils.js");

exports.fuzzer = fuzzer;
exports.config = config;
exports.mutator = mutator;

/* Define this to exclude other modules from instrumentation */
exports.target_module = null;
/* MANDATORY: harness function */
exports.fuzzer_test_one_input = null;
/* If true, the user has to call fuzzing_loop() manually in a callback
   (see Java example, fuzzing_loop cannot be called during script loading) */
exports.manual_loop_start = false;

// by default stages are from FidgetyAFL
exports.stages = [
  fuzzer.havoc_stage,
  fuzzer.splice_stage,
];

exports.fuzzing_loop = function () {

  if (exports.fuzzer_test_one_input === null) {
    throw "ERROR: fuzzer_test_one_input not set! Cannot start the fuzzing loop!";
  }

  var payload_memory = Memory.alloc(config.MAX_FILE);
  var payload_len = 0;

  function runner(/* ArrayBuffer */ arr_buf) {
    
    var b = new Uint8Array(arr_buf);
    var s = Math.min(b.length, config.MAX_FILE);
    Memory.writeByteArray(payload_memory, b, s);

    exports.fuzzer_test_one_input(payload_memory, s);

  }
  
  Process.setExceptionHandler(function (details) {
    send({
      "event": "crash",
      "err": details,
      "stage": fuzzer.stage_name
    }, payload_memory.readByteArray(payload_len));
    return false;
  });
  
  instr.start_tracing(Process.getCurrentThreadId(), exports.target_module);

  console.log(" >> Starting fuzzing loop...");
  
  while (true) {

    send({
      "event": "next",
      "stage": fuzzer.stage_name,
      "total_execs": fuzzer.total_execs,
    });

    var buf = undefined;
    var op = recv("input", function (val) {
      buf = utils.hex_to_arrbuf(val.buf);
      fuzzer.queue_cur = val.num;
      //val.was_fuzzed
    });

    op.wait();

    for(var stage of exports.stages)
        stage(buf, runner);

  }

}

rpc.exports.loop = function () {

  if (exports.manual_loop_start) return;

  exports.fuzzing_loop();

}

