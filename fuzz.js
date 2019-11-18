var utils   = require("./utils.js");
var config  = require("./config.js");
var mutator = require("./mutator.js");
var bitmap  = require("./bitmap.js");

exports.stage_name = "init";
exports.stage_cur  = 0;
exports.stage_max  = 0;

exports.fuzz_havoc = function (buf, callback, is_splice=false) {

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
    
    bitmap.common_fuzz_stuff(muted, callback);
 
  }

}

