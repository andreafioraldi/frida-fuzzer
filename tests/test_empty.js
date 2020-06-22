var config = require("../fuzz/config.js");

// if you want to modify config vars you need to do it before including the fuzz module
config.MAP_SIZE = 16;
config.SKIP_SCORE_FAV = true;

var fuzz = require("../fuzz");

var TARGET_MODULE = "test_empty";
var TARGET_FUNCTION = DebugSymbol.fromName("target_func").address;;
var RET_TYPE = "void";
var ARGS_TYPES = ['pointer', 'int'];

// { traps: 'all' } is needed for stalking
var func_handle = new NativeFunction(TARGET_FUNCTION, RET_TYPE, ARGS_TYPES, { traps: 'all' });

fuzz.target_module = TARGET_MODULE;

fuzz.fuzzer_test_one_input = function (/* Uint8Array */ payload) {

  var payload_mem = payload.buffer.unwrap();

  func_handle(payload_mem, payload.length);

}

console.log (" >> Agent loaded!");
