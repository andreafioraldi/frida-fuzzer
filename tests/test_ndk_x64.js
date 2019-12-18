var fuzz = require("../fuzz");

var TARGET_MODULE = "libnative-lib.so";
var TARGET_FUNCTION = Module.findExportByName(TARGET_MODULE, "target_func");
var RET_TYPE = "void";
var ARGS_TYPES = ['pointer', 'int'];

// { traps: 'all' } is needed for stalking
var func_handle = new NativeFunction(TARGET_FUNCTION, RET_TYPE, ARGS_TYPES, { traps: 'all' });

fuzz.target_module = TARGET_MODULE;

var payload_mem = Memory.alloc(fuzz.config.MAX_FILE);

fuzz.fuzzer_test_one_input = function (/* Uint8Array */ payload) {

  Memory.writeByteArray(payload_mem, payload, payload.length);

  func_handle(payload_mem, payload.length);

}

console.log (" >> Agent loaded!");
