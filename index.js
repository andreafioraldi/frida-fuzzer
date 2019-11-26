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

//var qbdi = require('./QBDI/usr/local/share/qbdi/frida-qbdi.js');
var qbdi = require('/usr/share/qbdi/frida-qbdi.js');
qbdi.import();

var fuzz = require("./fuzz.js");
var config = require("./config.js");

var vm = new QBDI();

/************************** USER CONFIGURABLE BITS ***************************/

//var TARGET_MODULE = "test_linux64";
var TARGET_MODULE = "libnative-lib.so";
Module.ensureInitialized(TARGET_MODULE);

//var TARGET_FUNCTION = DebugSymbol.fromName("target_func").address;
var TARGET_FUNCTION = Module.findExportByName(TARGET_MODULE, "target_func");

function fuzzer_test_one_input (payload, size) {

  vm.call(TARGET_FUNCTION, [payload, size]);

}

/*****************************************************************************/

rpc.exports.loop = function () {

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

  var state = vm.getGPRState();
  var stack = vm.allocateVirtualStack(state, 0x100000);

  vm.addInstrumentedModuleFromAddr(TARGET_FUNCTION);

  var user_data = { prev_loc: 0};
  var BasicBlockCallback = vm.newVMCallback(function(vm, evt, gpr, fpr, data) {

      var cur_loc = gpr.getRegister(REG_PC);
      cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
      cur_loc &= config.MAP_SIZE - 1;

      var x = fuzz.trace_bits.add(cur_loc ^ data.prev_loc);
      x.writeU8((x.readU8() +1) & 0xff);

      data.prev_loc = cur_loc >> 1;

      return VMAction.CONTINUE;
  });
  vm.addVMEventCB(VMEvent.BASIC_BLOCK_ENTRY, BasicBlockCallback, user_data);


  var payload_memory = Memory.alloc(config.MAX_FILE);
  var payload_len = 0;

  function runner(arr_buf) {
    
    var b = new Uint8Array(arr_buf);
    var s = Math.min(b.length, config.MAX_FILE);
    Memory.writeByteArray(payload_memory, b, s);

    fuzzer_test_one_input(payload_memory, s);

  }
  
  Process.setExceptionHandler(function (details) {
    send({
      "event": "crash",
      "err": details,
      "stage": fuzz.stage_name
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
      "stage": fuzz.stage_name,
      "total_execs": fuzz.total_execs,
    });

    var buf = undefined;
    var op = recv("input", function (val) {
      buf = hex_to_arrbuf(val.buf);
      //val.was_fuzzed
    });

    op.wait();

    try {
      /* RANDOM HAVOC */
      fuzz.fuzz_havoc(buf, runner, false);
    } catch(err) {
      return;
    }

  }

}


console.log(" >> Agent loaded.");

